(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/p2p_handshake.cpp at the pin: the version handshake
;;;; driven by up to a hundred messages of Core's types with fuzzed payloads,
;;;; from peers not yet connected, under a clock that jumps. Ours runs the
;;;; handshake on its own thread against the socket (PERFORM-INBOUND-HANDSHAKE
;;;; for an accepted connection, PERFORM-HANDSHAKE for one we dialled), so the
;;;; target is that function on one end of a loopback pair whose other end
;;;; writes the buffer's messages -- a VERSION with fuzzed fields usually first,
;;;; then VERACK, the negotiation messages Core accepts before it, and others
;;;; -- and hangs up.
;;;;
;;;; Beyond Core's no-crash (a declared refusal is the handshake failing; a
;;;; TYPE-ERROR or the like escaping is a crash): the handshake completes
;;;; exactly when Core's would make the peer fSuccessfullyConnected -- a
;;;; VERSION at or above MIN_PEER_PROTO_VERSION first, and a VERACK after it --
;;;; and the peer is :READY exactly when it completed.

(def-suite :fuzz-p2p-handshake-tests :in :bitcoin-lisp-tests
  :description "Core fuzz p2p_handshake.cpp over our version handshake")

(in-suite :fuzz-p2p-handshake-tests)

(defun %handshake-script (fdp)
  "A list of (command . payload) a peer sends: usually a VERSION first."
  (flet ((version ()
           (cons "version"
                 (bl.ser:make-version-message-bytes
                  :version (pick-value-in-array fdp (list 70016 70016 31800 31799 60000
                                                          (consume-integral-in-range fdp 0 #x7fffffff)))
                  :services (pick-value-in-array fdp (list #x409 #x409 0 (consume-integral fdp :u64)))
                  :timestamp (consume-integral fdp :u32)
                  :start-height (consume-integral-in-range fdp 0 1000)
                  :relay (consume-bool fdp) :nonce (consume-integral fdp :u64))))
         (other ()
           (call-one-of fdp
             (cons "verack" (make-array 0 :element-type '(unsigned-byte 8)))
             (cons "verack" (make-array 0 :element-type '(unsigned-byte 8)))
             (cons "wtxidrelay" (make-array 0 :element-type '(unsigned-byte 8)))
             (cons "sendaddrv2" (make-array 0 :element-type '(unsigned-byte 8)))
             (cons "sendheaders" (make-array 0 :element-type '(unsigned-byte 8)))
             (cons "sendtxrcncl" (consume-random-length-byte-vector fdp 16))
             (cons (pick-value-in-array fdp +fuzz-net-message-types+) (consume-random-length-byte-vector fdp 64)))))
    (append (list (if (plusp (consume-integral-in-range fdp 0 7)) (version) (other)))
            (loop repeat (consume-integral-in-range fdp 0 14)
                  collect (if (zerop (consume-integral-in-range fdp 0 7)) (version) (other))))))

(defun %handshake-expected-p (script)
  "Core's reading (net_processing.cpp:3585-3830): anything before the first
VERSION is ignored (`non-version message before version handshake'); that
VERSION must be at or above MIN_PEER_PROTO_VERSION (31800) or the peer is
disconnected; later VERSIONs are redundant and ignored; and a VERACK after
it makes the peer fSuccessfullyConnected. With transaction reconciliation
off (Core's default) a sendtxrcncl is ignored, and every other message before
VERACK is `Unsupported message prior to verack'."
  (let ((at (position "version" script :key #'car :test #'string=)))
    (and at
         (handler-case
             (>= (bl.ser:version-message-version
                  (bl.bytes:with-byte-reader (in (cdr (nth at script))) (bl.ser:read-version-message in)))
                 31800)
           (error () nil))
         (find "verack" (nthcdr (1+ at) script) :key #'car :test #'string=)
         t)))

(define-fuzz-target p2p-handshake
    (buffer :core "p2p_handshake.cpp:41-108" :iterations 60 :max-len 500)
  "The version handshake, inbound or outbound, over any messages a peer sends
first: no crash; it completes, and the peer is ready, exactly when the peer
sent a VERSION Core accepts first and a VERACK after it."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (inbound (consume-bool fdp))
         (script (%handshake-script fdp))
         (bytes (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                       (mapcar (lambda (m) (bl.ser:serialize-message (car m) (cdr m))) script))))
    (call-with-scripted-peer
     bytes
     (lambda (socket)
       (let* ((bl.net:*v2-transport-enabled* nil)
              (bl:*tx-reconciliation* nil)
              (conn (make-test-connection :socket socket :host "127.0.0.1" :port 18444 :connected t))
              (peer (if inbound
                        (bl.net:make-inbound-peer conn "127.0.0.1")
                        (bl.net:make-peer :connection conn :state :connected :address "127.0.0.1")))
              (done (handler-case
                        (with-private-outbound-nonces
                          (if inbound
                              (bl.net:perform-inbound-handshake peer :timeout 3)
                              (bl.net:perform-handshake peer :try-v2 nil :conn-type :manual)))
                      (error (c)
                        (unless (%declared-refusal-p c)
                          (signal-fuzz-violation
                           (format nil "crash: ~S in the ~:[outbound~;inbound~] handshake: ~A"
                                   (type-of c) inbound c)))
                        nil))))
         (fuzz-assert (eq (fuzz-sabotage (and done t)) (%handshake-expected-p script))
                      "the ~:[outbound~;inbound~] handshake ~:[failed~;completed~] on ~{~A~^ ~}"
                      inbound done (mapcar #'car script))
         (fuzz-assert (eq (eq (bl.net:peer-state peer) :ready) (and done t))
                      "the handshake answered ~S with the peer ~S" done (bl.net:peer-state peer)))))))
