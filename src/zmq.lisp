(in-package #:bitcoin-lisp)

;;;; ZMQ notification interface (Bitcoin Core src/zmq/)
;;;;
;;;; Five PUB sockets that broadcast what the node just did, so external
;;;; software can react without polling the RPC. Each is bound to its own
;;;; -zmqpub<topic>=<address>, and every message is three parts: the topic, the
;;;; body, and a per-topic little-endian uint32 counter that lets a subscriber
;;;; notice it missed something.
;;;;
;;;; libzmq is loaded LAZILY -- only when a -zmqpub* option is actually
;;;; configured. A host without libzmq therefore runs the node perfectly well
;;;; as long as ZMQ is off, which keeps a shared library out of the critical
;;;; path of simply starting up.

(defvar *zmq-library-loaded* nil
  "T once libzmq has been loaded into this image.")

(defconstant +zmq-pub+ 1 "ZMQ_PUB socket type.")
(defconstant +zmq-sndmore+ 2 "ZMQ_SNDMORE: another frame follows this one.")
(defconstant +zmq-linger+ 17
  "ZMQ_LINGER. It defaults to -1, meaning zmq_close blocks FOREVER on messages
still queued for a subscriber that has gone away. Core sets it to 0 immediately
before closing (zmqpublishnotifier.cpp:186) and so do we.")
(defconstant +zmq-sndhwm+ 23 "ZMQ_SNDHWM: outbound high-water mark.")

(defconstant +default-zmq-sndhwm+ 1000
  "Core CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM. Messages beyond this many
queued for a slow subscriber are DROPPED rather than allowed to grow the node's
memory without bound -- a subscriber that cannot keep up must not be able to
stall or exhaust the node.")

(defparameter +zmq-topics+
  '("hashblock" "hashtx" "rawblock" "rawtx" "sequence")
  "Core's five publishers (zmqpublishnotifier.cpp:34-38).")

(defun ensure-zmq-library ()
  "Load libzmq on first use. Returns T on success, NIL (with a warning) if the
library is absent -- the caller then runs without ZMQ rather than failing to
start."
  (or *zmq-library-loaded*
      (handler-case
          (progn
            (cffi:load-foreign-library '(:default "libzmq"))
            (setf *zmq-library-loaded* t))
        (error (e)
          (log-error "ZMQ requested but libzmq could not be loaded: ~A" e)
          nil))))

(defun zmq-version ()
  "The linked libzmq's version as a string, or NIL if it is not loaded."
  (when *zmq-library-loaded*
    (cffi:with-foreign-objects ((major :int) (minor :int) (patch :int))
      (cffi:foreign-funcall "zmq_version" :pointer major :pointer minor
                                          :pointer patch :void)
      (format nil "~D.~D.~D" (cffi:mem-ref major :int)
              (cffi:mem-ref minor :int) (cffi:mem-ref patch :int)))))

(defun %zmq-strerror ()
  (if *zmq-library-loaded*
      (let ((errno (cffi:foreign-funcall "zmq_errno" :int)))
        (cffi:foreign-string-to-lisp
         (cffi:foreign-funcall "zmq_strerror" :int errno :pointer)))
      "libzmq not loaded"))

(defstruct zmq-publisher
  "One PUB socket for one topic at one address."
  (topic "" :type string)
  (address "" :type string)
  (socket nil)
  (hwm +default-zmq-sndhwm+ :type integer)
  ;; Per-topic counter, incremented AFTER a successful send (Core :205), so a
  ;; subscriber sees a gap exactly when a message was dropped.
  (sequence 0 :type (unsigned-byte 32)))

(defvar *zmq-context* nil "The shared libzmq context, or NIL.")
(defvar *zmq-publishers* '() "Active ZMQ-PUBLISHER structs.")

(defvar *zmq-publisher-specs* '()
  "What -zmqpub* asked for, as (topic address hwm), recorded by
APPLY-CONFIG-GLOBALS and acted on by START-NODE. Keeping the parse separate
from the socket bind means a bad address is reported while reading the config,
not halfway through startup.")

(defun %zmq-setsockopt-int (socket option value)
  (cffi:with-foreign-object (v :int)
    (setf (cffi:mem-ref v :int) value)
    (cffi:foreign-funcall "zmq_setsockopt" :pointer socket :int option
                                           :pointer v :size 4 :int)))

(defun %zmq-open-publisher (topic address hwm)
  "Bind one PUB socket, or return NIL after logging why. A publisher that
cannot bind must not take the node down: Core reports and carries on."
  (let ((socket (cffi:foreign-funcall "zmq_socket" :pointer *zmq-context*
                                                   :int +zmq-pub+ :pointer)))
    (when (cffi:null-pointer-p socket)
      (log-error "ZMQ: could not create a PUB socket for ~A: ~A" topic (%zmq-strerror))
      (return-from %zmq-open-publisher nil))
    (%zmq-setsockopt-int socket +zmq-sndhwm+ hwm)
    (let ((rc (cffi:with-foreign-string (a address)
                (cffi:foreign-funcall "zmq_bind" :pointer socket :pointer a :int))))
      (when (minusp rc)
        (log-error "ZMQ: could not bind ~A to ~A: ~A" topic address (%zmq-strerror))
        (%zmq-setsockopt-int socket +zmq-linger+ 0)
        (cffi:foreign-funcall "zmq_close" :pointer socket :int)
        (return-from %zmq-open-publisher nil)))
    (log-info "ZMQ: publishing ~A to ~A (hwm ~D)" topic address hwm)
    (make-zmq-publisher :topic topic :address address :socket socket :hwm hwm)))

(defun zmq-start-publishers (specs)
  "Start a publisher per entry of SPECS, a list of (topic address hwm).
Returns the number started. Loads libzmq on the first entry; with an empty
SPECS nothing is loaded at all, which is the whole point of the lazy load."
  (when (null specs)
    (return-from zmq-start-publishers 0))
  (unless (ensure-zmq-library)
    (return-from zmq-start-publishers 0))
  (unless *zmq-context*
    (setf *zmq-context* (cffi:foreign-funcall "zmq_ctx_new" :pointer))
    (when (cffi:null-pointer-p *zmq-context*)
      (setf *zmq-context* nil)
      (log-error "ZMQ: could not create a context: ~A" (%zmq-strerror))
      (return-from zmq-start-publishers 0)))
  (let ((started 0))
    (dolist (spec specs started)
      (destructuring-bind (topic address &optional (hwm +default-zmq-sndhwm+)) spec
        (let ((pub (%zmq-open-publisher topic address hwm)))
          (when pub
            (push pub *zmq-publishers*)
            (incf started)))))))

(defun zmq-stop-publishers ()
  "Close every publisher and the context. LINGER is set to 0 first, exactly as
Core does, or this blocks forever on anything still queued."
  (dolist (pub *zmq-publishers*)
    (let ((socket (zmq-publisher-socket pub)))
      (when socket
        (%zmq-setsockopt-int socket +zmq-linger+ 0)
        (cffi:foreign-funcall "zmq_close" :pointer socket :int)
        (setf (zmq-publisher-socket pub) nil))))
  (setf *zmq-publishers* '())
  (when *zmq-context*
    (cffi:foreign-funcall "zmq_ctx_term" :pointer *zmq-context* :int)
    (setf *zmq-context* nil))
  t)

(defun %zmq-send-frame (socket bytes more)
  "One frame. Returns T on success."
  (let ((n (length bytes)))
    (cffi:with-foreign-pointer (buf (max n 1))
      (dotimes (i n)
        (setf (cffi:mem-aref buf :unsigned-char i) (aref bytes i)))
      (>= (cffi:foreign-funcall "zmq_send" :pointer socket :pointer buf
                                           :size n :int (if more +zmq-sndmore+ 0)
                                           :int)
          0))))

(defun zmq-publish (topic body)
  "Publish BODY on TOPIC to whichever publisher serves it (Core
SendZmqMessage): three frames — topic, body, and a little-endian uint32
sequence. The counter advances only after a successful send, so a gap in it
means a message was genuinely lost rather than merely renumbered."
  (let ((pub (find topic *zmq-publishers* :key #'zmq-publisher-topic :test #'string=)))
    (when (and pub (zmq-publisher-socket pub))
      (let* ((socket (zmq-publisher-socket pub))
             (seq (zmq-publisher-sequence pub))
             (seq-bytes (make-array 4 :element-type '(unsigned-byte 8))))
        (dotimes (i 4)
          (setf (aref seq-bytes i) (ldb (byte 8 (* 8 i)) seq)))
        (when (and (%zmq-send-frame socket
                                    (map '(vector (unsigned-byte 8)) #'char-code topic)
                                    t)
                   (%zmq-send-frame socket body t)
                   (%zmq-send-frame socket seq-bytes nil))
          (setf (zmq-publisher-sequence pub) (ldb (byte 32 0) (1+ seq)))
          t)))))

(defun %zmq-reversed (hash)
  "Core sends every hash in DISPLAY order — reversed from internal byte order
(zmqpublishnotifier.cpp:221-223). A subscriber comparing against a block
explorer would otherwise see a mirrored hash and conclude nothing matches."
  (reverse (coerce hash '(vector (unsigned-byte 8)))))

(defun zmq-notify-hash-block (hash)
  (zmq-publish "hashblock" (%zmq-reversed hash)))

(defun zmq-notify-hash-tx (txid)
  (zmq-publish "hashtx" (%zmq-reversed txid)))

(defun zmq-notify-raw-block (bytes)
  (zmq-publish "rawblock" bytes))

(defun zmq-notify-raw-tx (bytes)
  (zmq-publish "rawtx" bytes))

(defun zmq-notify-sequence (hash label &optional mempool-sequence)
  "The sequence topic (Core SendSequenceMsg): 32-byte hash, a one-character
LABEL, and for the mempool events an 8-byte little-endian counter.

LABEL is #\\A (tx added to mempool), #\\R (tx removed), #\\C (block connected)
or #\\D (block disconnected). The block events carry no counter."
  (let* ((h (%zmq-reversed hash))
         (n (if mempool-sequence 41 33))
         (data (make-array n :element-type '(unsigned-byte 8))))
    (replace data h)
    (setf (aref data 32) (char-code label))
    (when mempool-sequence
      (dotimes (i 8)
        (setf (aref data (+ 33 i)) (ldb (byte 8 (* 8 i)) mempool-sequence))))
    (zmq-publish "sequence" data)))

(defun zmq-notifications-info ()
  "What getzmqnotifications reports: one entry per active publisher."
  (mapcar (lambda (pub)
            (list (format nil "pub~A" (zmq-publisher-topic pub))
                  (zmq-publisher-address pub)
                  (zmq-publisher-hwm pub)))
          (reverse *zmq-publishers*)))

;;;; --- Configuration ---

(defun zmq-specs-from-config (merged)
  "The publishers -zmqpub<topic>=<address> asks for, as (topic address hwm),
in +ZMQ-TOPICS+ order. -zmqpub<topic>hwm sets that topic's high-water mark;
Core reads it per topic, not globally (zmqnotificationinterface.cpp:69).

Returns NIL when no topic is configured, which is what keeps libzmq unloaded on
a node that does not use ZMQ."
  (flet ((lk (k) (let ((c (assoc k merged :test #'string=))) (and c (cdr c)))))
    (loop for topic in +zmq-topics+
          for address = (lk (format nil "zmqpub~A" topic))
          when (and address (plusp (length address)))
            collect (list topic
                          address
                          (let ((h (lk (format nil "zmqpub~Ahwm" topic))))
                            (if h
                                (let ((n (conf-parse-int h)))
                                  (when (minusp n)
                                    (config-error "Invalid value for -zmqpub~Ahwm=~A" topic h))
                                  n)
                                +default-zmq-sndhwm+))))))

;;;; --- Node events (Core CZMQNotificationInterface) ---

(defun zmq-topic-active-p (topic)
  "T when something is actually publishing TOPIC. Callers check this BEFORE
serializing a block or transaction: rawblock is megabytes, and paying that on
every connected block for a topic nobody subscribes to would be a tax on the
whole node for an unused feature."
  (and *zmq-publishers*
       (find topic *zmq-publishers* :key #'zmq-publisher-topic :test #'string=)
       t))

(defun zmq-notify-transaction (tx txid)
  "The hashtx / rawtx pair for one transaction (Core NotifyTransaction)."
  (when (zmq-topic-active-p "hashtx")
    (zmq-notify-hash-tx txid))
  (when (zmq-topic-active-p "rawtx")
    (zmq-notify-raw-tx (bl.ser:serialize-transaction tx))))

(defun zmq-notify-tx-accepted (tx txid mempool-sequence)
  "A transaction entered the mempool (Core TransactionAddedToMempool): the
hashtx/rawtx pair, then a sequence 'A' carrying the mempool counter."
  (when *zmq-publishers*
    (zmq-notify-transaction tx txid)
    (when (zmq-topic-active-p "sequence")
      (zmq-notify-sequence txid #\A mempool-sequence))))

(defun zmq-notify-tx-removed (txid mempool-sequence)
  "A transaction left the mempool for a reason OTHER than being mined (Core
TransactionRemovedFromMempool: \"Called for all non-block inclusion reasons\").
A mined transaction is reported by the block notification instead."
  (when (zmq-topic-active-p "sequence")
    (zmq-notify-sequence txid #\R mempool-sequence)))

(defun zmq-notify-block-connected (block hash)
  "Core BlockConnected: every transaction in the block first, then the block
itself and a sequence 'C'."
  (when *zmq-publishers*
    (when (or (zmq-topic-active-p "hashtx") (zmq-topic-active-p "rawtx"))
      ;; BITCOIN-BLOCK-TRANSACTIONS is a LIST (types.lisp:534), not a vector.
      (loop for tx in (bl.ser:bitcoin-block-transactions block)
            do (zmq-notify-transaction
                tx (bl.ser:transaction-hash tx))))
    (when (zmq-topic-active-p "hashblock")
      (zmq-notify-hash-block hash))
    (when (zmq-topic-active-p "rawblock")
      (zmq-notify-raw-block (bl.ser:serialize-witness-block block)))
    (when (zmq-topic-active-p "sequence")
      (zmq-notify-sequence hash #\C))))

(defun zmq-notify-block-disconnected (block hash)
  "Core BlockDisconnected: every transaction in the block, then a sequence 'D'.
No rawblock/hashblock — those announce the tip moving FORWARD."
  (when *zmq-publishers*
    (when (or (zmq-topic-active-p "hashtx") (zmq-topic-active-p "rawtx"))
      ;; BITCOIN-BLOCK-TRANSACTIONS is a LIST (types.lisp:534), not a vector.
      (loop for tx in (bl.ser:bitcoin-block-transactions block)
            do (zmq-notify-transaction
                tx (bl.ser:transaction-hash tx))))
    (when (zmq-topic-active-p "sequence")
      (zmq-notify-sequence hash #\D))))
