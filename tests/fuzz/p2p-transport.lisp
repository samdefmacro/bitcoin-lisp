(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/p2p_transport_serialization.cpp (the v1 target) and
;;;; net.cpp's ReceiveMsgBytes at the pin: bytes a peer sends, framed or not,
;;;; through the v1 receiver. Ours is RECEIVE-MESSAGE on a peer whose
;;;; connection's far end is a loopback socket that writes the buffer's bytes
;;;; and closes -- the resumable reader and the header/payload framing exactly
;;;; as the pump drives them.
;;;;
;;;; Core asserts of each message it delivers that its type is at most twelve
;;;; characters, its raw size is the header plus the payload and no more than
;;;; was sent, and that it re-sends as a message. Ours asserts the stronger
;;;; thing a whole receiver can be held to: the sequence of messages delivered,
;;;; and where delivery stops, is Core's V1Transport reading of the same bytes
;;;; (net.cpp:737-839, restated in %V1-REFERENCE-MESSAGES) -- a wrong magic or
;;;; an oversized length ends the connection, a wrong checksum or an invalid
;;;; type drops that one message and keeps reading -- and every message
;;;; delivered re-frames (SERIALIZE-MESSAGE) to the very bytes it came from.

(def-suite :fuzz-p2p-transport-tests :in :bitcoin-lisp-tests
  :description "Core fuzz p2p_transport_serialization.cpp (v1) and net.cpp ReceiveMsgBytes")

(in-suite :fuzz-p2p-transport-tests)

(defun %v1-type-valid-p (field)
  "Core CMessageHeader::IsMessageTypeValid (protocol.cpp:26-43) over the
12-byte FIELD: printable ASCII up to the first NUL, only NULs after it."
  (let ((end (or (position 0 field) 12)))
    (and (every (lambda (b) (<= #x20 b #x7e)) (subseq field 0 end))
         (every #'zerop (subseq field end)))))

(defun %v1-reference-messages (bytes magic)
  "Core's V1Transport over BYTES then EOF: (values MESSAGES END) where
MESSAGES are the (type-field . payload) it delivers in order and END is
:disconnect (bad magic or oversized length), :incomplete (a frame cut short
by the end of the bytes) or :clean."
  (let ((pos 0) (out '()))
    (loop
      (when (= pos (length bytes)) (return (values (nreverse out) :clean)))
      (when (< (- (length bytes) pos) 24) (return (values (nreverse out) :incomplete)))
      (let* ((header (subseq bytes pos (+ pos 24)))
             (size (logior (aref header 16) (ash (aref header 17) 8)
                           (ash (aref header 18) 16) (ash (aref header 19) 24))))
        (unless (equalp (subseq header 0 4) magic)
          (return (values (nreverse out) :disconnect)))
        (when (> size bl:+max-message-payload+)
          (return (values (nreverse out) :disconnect)))
        (when (< (- (length bytes) pos 24) size)
          (return (values (nreverse out) :incomplete)))
        (let ((payload (subseq bytes (+ pos 24) (+ pos 24 size))))
          (incf pos (+ 24 size))
          (when (and (equalp (subseq header 20 24) (subseq (bl.ser:compute-checksum payload) 0 4))
                     (%v1-type-valid-p (subseq header 4 16)))
            (push (cons (subseq header 4 16) payload) out)))))))

(defun %fuzz-v1-frame (fdp magic)
  "One v1 frame: Core's harness's magic and checksum assists, as the usual case
of a frame that is right in every field, with the type, length, checksum or
magic wrong now and then."
  (let* ((type (let ((field (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
                     (name (if (consume-bool fdp)
                               (map '(vector (unsigned-byte 8)) #'char-code
                                    (pick-value-in-array fdp +fuzz-net-message-types+))
                               (consume-bytes fdp (consume-integral-in-range fdp 0 12)))))
                 (replace field name)))
         (payload (consume-bytes fdp (consume-integral-in-range fdp 0 300)))
         (size (if (zerop (consume-integral-in-range fdp 0 15))
                   (pick-value-in-array fdp (list (1+ (length payload)) (consume-integral fdp :u32)
                                                  (1+ bl:+max-message-payload+)))
                   (length payload)))
         (checksum (if (zerop (consume-integral-in-range fdp 0 7))
                       (consume-bytes fdp 4)
                       (subseq (bl.ser:compute-checksum payload) 0 4)))
         (magic (if (zerop (consume-integral-in-range fdp 0 15)) (consume-bytes fdp 4) magic)))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 magic type
                 (vector (ldb (byte 8 0) size) (ldb (byte 8 8) size) (ldb (byte 8 16) size) (ldb (byte 8 24) size))
                 checksum payload)))

(defun %drain-v1-peer (bytes)
  "Deliver BYTES from a loopback peer that then hangs up, and read messages
off our side with RECEIVE-MESSAGE until the connection is gone (at most 2,000
reads): (values MESSAGES STATE), MESSAGES the (command . payload) delivered,
STATE the peer's state at the end."
  (call-with-scripted-peer
   bytes
   (lambda (socket)
     (let ((peer (bl.net:make-peer :connection (make-test-connection :socket socket :connected t)
                                   :state :ready :address "127.0.0.1"))
           (out '()))
       (loop repeat 2000
             do (multiple-value-bind (command payload) (bl.net:receive-message peer :timeout 1)
                  ;; NIL with no :INCOMPLETE is a message dropped (a bad
                  ;; checksum or type: the reader goes on) or the connection
                  ;; gone; only the second ends the drain.
                  (cond (command (push (cons command payload) out))
                        ((eq payload :incomplete) (sleep 0.0005))
                        ((eq (bl.net:peer-state peer) :disconnected) (return)))))
       (values (nreverse out) (bl.net:peer-state peer))))))

(define-fuzz-target p2p-transport-serialization
    (buffer :core "p2p_transport_serialization.cpp:35-106; net.cpp:30-83" :iterations 150 :max-len 1500)
  "Frames a peer sends, right or wrong in any field, reach the node exactly as
Core's V1Transport delivers them: the same messages in the same order, the
connection dropped where Core drops it, and every delivered message re-framing
to the bytes it came from."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (magic bl.ser:*network-magic*)
         (bytes (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                       (loop repeat (consume-integral-in-range fdp 0 4)
                             collect (%fuzz-v1-frame fdp magic))))
         (bytes (if (zerop (consume-integral-in-range fdp 0 7))
                    (concatenate '(simple-array (unsigned-byte 8) (*))
                                 bytes (consume-remaining-bytes fdp))
                    bytes)))
    (multiple-value-bind (want end) (%v1-reference-messages bytes magic)
      (multiple-value-bind (got state) (%drain-v1-peer bytes)
        (fuzz-assert (= (length (fuzz-sabotage got)) (length want))
                     "~D messages delivered where Core delivers ~D (~A)" (length got) (length want) end)
        (loop for (command . payload) in got
              for (field . want-payload) in want
              do (fuzz-assert (<= (length command) 12) "a message type of ~D characters" (length command))
                 (fuzz-assert (equalp (bl.ser:serialize-message command payload)
                                      (concatenate '(simple-array (unsigned-byte 8) (*))
                                                   magic field
                                                   (subseq (bl.ser:serialize-message command payload) 16 24)
                                                   want-payload))
                              "~S does not re-frame to the bytes Core read" command))
        (when (eq end :disconnect)
          (fuzz-assert (eq state :disconnected) "Core drops this connection; ours is ~S" state))))))

;;; --- p2p_transport_bidirectional_v2 -------------------------------------------------

(defun %fuzz-message-type (fdp)
  "A message type: one of Core's (most of which have a BIP324 short ID), or up
to twelve printable characters (the long encoding)."
  (if (consume-bool fdp)
      (pick-value-in-array fdp +fuzz-net-message-types+)
      (map 'string (lambda (b) (code-char (+ 32 (mod b 95))))
           (consume-bytes fdp (consume-integral-in-range fdp 0 12)))))

(defun %v2-receive-within (peer seconds)
  "(values COMMAND PAYLOAD) of the next message RECEIVE-MESSAGE takes off PEER
within SECONDS, or NIL."
  (loop with deadline = (+ (get-internal-real-time) (* seconds internal-time-units-per-second))
        do (multiple-value-bind (command payload) (bl.net:receive-message peer :timeout 1)
             (cond (command (return (values command payload)))
                   ((not (eq payload :incomplete)) (return nil))
                   ((> (get-internal-real-time) deadline) (return nil))
                   (t (sleep 0.0005))))))

(define-fuzz-target p2p-transport-bidirectional-v2
    (buffer :core "p2p_transport_serialization.cpp:318-360 (bidirectional_v2)" :iterations 40 :max-len 3000)
  "Two nodes that complete the BIP324 handshake over a socket pair -- each with
its own random garbage -- then exchange messages of any type and payload in
both directions, several in flight at a time: every message arrives, in
order, with its type and payload intact."
  (unless (bl.crypto:ellswift-available-p)
    (return-from fuzz-target/p2p-transport-bidirectional-v2))
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (%with-loopback-pair (client server)
      (let* ((client-transport nil)
             (initiator (bt:make-thread
                         (lambda ()
                           (handler-case
                               (setf client-transport (prog1 (%v2t-initiate client :timeout 20)
                                                        (%v2t-drain client)))
                             (error (e) (setf client-transport e))))
                         :name "fuzz-v2-initiator"))
             (server-transport (prog1 (%v2t-detect server :timeout 20) (%v2t-drain server))))
        (sb-thread:join-thread initiator :default nil :timeout 30)
        (fuzz-assert (and (bl.net:v2-transport-p (fuzz-sabotage server-transport))
                          (bl.net:v2-transport-p client-transport))
                     "the v2 handshake failed: ~S / ~S" client-transport server-transport)
        (setf (bl.net:connection-transport client) client-transport
              (bl.net:connection-transport server) server-transport)
        (let ((ends (vector (bl.net:make-peer :connection client :state :ready :address "127.0.0.1")
                            (bl.net:make-peer :connection server :state :ready :address "127.0.0.1"))))
          (limited-while ((plusp (remaining-bytes fdp)) 200)
            (let* ((from (consume-integral-in-range fdp 0 1))
                   (to (- 1 from))
                   (sent (loop repeat (consume-integral-in-range fdp 1 3)
                               collect (cons (%fuzz-message-type fdp)
                                             (consume-bytes fdp (consume-integral-in-range fdp 0 1500))))))
              (dolist (m sent)
                (bl.net:send-message (aref ends from) (bl.ser:serialize-message (car m) (cdr m))))
              (%v2t-drain (if (zerop from) client server))
              (dolist (m sent)
                (multiple-value-bind (command payload) (%v2-receive-within (aref ends to) 10)
                  (fuzz-assert (and (equal command (car m)) (equalp (fuzz-sabotage payload) (cdr m)))
                               "sent ~S (~D bytes), received ~S (~D bytes)"
                               (car m) (length (cdr m)) command (length payload)))))))))))

;;; --- BIP324 detection and handshake on arbitrary bytes ------------------------------

(define-fuzz-target p2p-v2-garbage
    (buffer :core "p2p_transport_serialization.cpp:109-316 (the v2 receiver's inputs)" :iterations 150 :max-len 600)
  "Whatever an inbound peer sends first -- a v1 VERSION header, one on the
wrong network, a key and garbage, or noise -- the responder's v1/v2 sniff and
handshake end without a crash, and call the peer v1 exactly when its first
sixteen bytes are our network's VERSION header."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (v1-prefix (subseq (bl.ser:serialize-message "version" (make-array 0 :element-type '(unsigned-byte 8)))
                            0 16))
         (bytes (call-one-of fdp
                  (concatenate '(simple-array (unsigned-byte 8) (*)) v1-prefix (consume-remaining-bytes fdp))
                  (let ((b (copy-seq v1-prefix)))
                    (setf (aref b (consume-integral-in-range fdp 0 15)) (consume-integral fdp :u8))
                    (concatenate '(simple-array (unsigned-byte 8) (*)) b (consume-remaining-bytes fdp)))
                  (consume-remaining-bytes fdp))))
    (call-with-scripted-peer
     bytes
     (lambda (socket)
       (let* ((conn (make-test-connection :socket socket :connected t))
              (result (%v2t-detect conn :timeout 3)))
         (fuzz-assert (eq (eq (fuzz-sabotage result) :v1)
                          (and (>= (length bytes) 16) (equalp (subseq bytes 0 16) v1-prefix)))
                      "the sniff answered ~S for a first sixteen bytes of ~A" result
                      (bl.crypto:bytes-to-hex (subseq bytes 0 (min 16 (length bytes))))))))))

;;; --- p2p_transport_bidirectional and _v1v2: SimulationTest --------------------------
;;;
;;; Core's SimulationTest (p2p_transport_serialization.cpp:107-337) drives two
;;; Transport objects with fragmented, interleaved sends and receives and
;;; asserts that every message arrives, in order and intact. Ours has no
;;; Transport object to hand bytes to: a side SENDS by writing a fuzz-chosen
;;; prefix of its framed bytes onto a loopback socket (SEND-BYTES), and
;;; RECEIVES by asking RECEIVE-MESSAGE once, which takes whatever the kernel
;;; has delivered -- so a message may be split at any byte, and a receive may
;;; find half a header, as Core's fragmentation produces. Core's
;;; GetBytesToSend consistency checks are about its Transport API and have no
;;; counterpart; its receive-side assertions all port.

(defun %fuzz-sim-message-type (fdp)
  "SimulationTest's msg_type_fn (:135-153): a u8; 0xFF builds a valid type of
up to twelve printable characters from the buffer, anything else indexes
Core's ALL_NET_MESSAGE_TYPES."
  (let ((v (consume-integral fdp :u8)))
    (if (= v #xff)
        (with-output-to-string (s)
          (loop repeat 12
                for c = (consume-integral fdp :i8)
                while (<= 32 c 126)
                do (write-char (code-char c) s)))
        (nth (mod v (length +fuzz-net-message-types+)) +fuzz-net-message-types+))))

(defun %fuzz-sim-make-message (fdp rng first)
  "SimulationTest's make_msg_fn (:156-169): a VERSION first, then any type;
up to 75 kB of payload from the RNG."
  (cons (if first "version" (%fuzz-sim-message-type fdp))
        (insecure-rand-bytes rng (consume-integral-in-range fdp 0 75000 32))))

(defun %fuzz-sim-receive (ends side expected)
  "recv_fn (:244-292) for the bytes SIDE sent: one RECEIVE-MESSAGE on the
other end. A delivered message must be the front of SIDE's queue in the
vector EXPECTED; returns T when a message was delivered."
  (multiple-value-bind (command payload) (bl.net:receive-message (aref ends (- 1 side)) :timeout 1)
    (cond (command
           (let ((want (pop (aref expected side))))
             (fuzz-assert want "side ~D received ~S that side ~D never sent" (- 1 side) command side)
             (fuzz-assert (and (equal command (car want))
                               (equalp (fuzz-sabotage (coerce payload '(vector (unsigned-byte 8))))
                                       (cdr want)))
                          "side ~D received ~S (~D bytes) where ~S (~D bytes) was sent"
                          (- 1 side) command (length payload) (car want) (length (cdr want))))
           t)
          (t (fuzz-assert (eq payload :incomplete)
                          "side ~D's reader failed on bytes side ~D sent intact" (- 1 side) side)
             nil))))

(defun %fuzz-transport-simulation (fdp rng ends &key (ready-p (lambda (side) (declare (ignore side)) t)))
  "SimulationTest (:107-337) over the two peers ENDS (index 0 the initiator).
READY-P says whether a side's transport takes messages yet (a v2 responder
still sniffing for v1 takes none, as V2Transport::SetMessageToSend refuses
before READY) and whether its reader may run. Returns how many bytes each side
put on the wire, as a two-element vector."
  (let ((sent (vector 0 0))
        (pending (vector (make-array 0 :element-type '(unsigned-byte 8))
                         (make-array 0 :element-type '(unsigned-byte 8))))
        (expected (vector '() '()))
        (next (vector (%fuzz-sim-make-message fdp rng t) (%fuzz-sim-make-message fdp rng t))))
    (labels ((conn (side) (bl.net:peer-connection (aref ends side)))
             (new-msg (side)
               ;; new_msg_fn (:206-224): a transport takes the next message
               ;; only once the previous one is wholly on the wire (V1Transport
               ;; ::SetMessageToSend), and never with 16 unreceived.
               (when (and (funcall ready-p side)
                          (< (length (aref expected side)) 16)
                          (zerop (length (aref pending side))))
                 (let ((m (aref next side)))
                   (setf (aref pending side) (bl.ser:serialize-message (car m) (cdr m)))
                   (setf (aref expected side) (append (aref expected side) (list m)))
                   (setf (aref next side) (%fuzz-sim-make-message fdp rng nil)))))
             (send (side everything)
               ;; send_fn (:227-241): a prefix of what is to be sent.
               (let* ((bytes (aref pending side))
                      (n (if everything (length bytes) (consume-integral-in-range fdp 0 (length bytes)))))
                 (when (plusp n)
                   (fuzz-assert (bl.net:send-bytes (conn side) (subseq bytes 0 n))
                                "side ~D could not send" side)
                   (%v2t-drain (conn side) :seconds 2)
                   (setf (aref pending side) (subseq bytes n))
                   (incf (aref sent side) n)
                   t)))
             (recv (side)
               (and (funcall ready-p (- 1 side))
                    (%fuzz-sim-receive ends side expected))))
      (limited-while ((plusp (remaining-bytes fdp)) 1000)
        (call-one-of fdp
          (new-msg 0) (new-msg 1)
          (send 0 nil) (send 1 nil)
          (recv 0) (recv 1)))
      ;; Flush (:308-316): send everything, receive until both queues are
      ;; empty. The kernel delivers when it delivers, so this waits -- up to
      ;; a deadline that only a lost message reaches.
      (loop with deadline = (+ (get-internal-real-time) (* 20 internal-time-units-per-second))
            until (and (null (aref expected 0)) (null (aref expected 1))
                       (zerop (length (aref pending 0))) (zerop (length (aref pending 1))))
            do (dotimes (side 2)
                 (when (funcall ready-p side) (send side t))
                 (loop while (recv side)))
               (when (> (get-internal-real-time) deadline) (return))
               (sleep 0.001))
      ;; :319-325: nothing left in flight, every message received.
      (fuzz-assert (and (null (aref expected 0)) (null (aref expected 1)))
                   "messages never arrived: ~D from side 0, ~D from side 1"
                   (length (aref expected 0)) (length (aref expected 1))))
    sent))

(defun %fuzz-v1-ends (client server)
  "Two v1 peers over the loopback pair's connections."
  (vector (bl.net:make-peer :connection client :state :ready :address "127.0.0.1")
          (bl.net:make-peer :connection server :state :ready :address "127.0.0.1")))

(define-fuzz-target p2p-transport-bidirectional
    (buffer :core "p2p_transport_serialization.cpp:375-384 (SimulationTest :107-337)"
            :iterations 30 :max-len 1500)
  "Two v1 transports exchange messages of any type and up to 75 kB, the
bytes of each written in fragments of any size interleaved with reads on
both ends: every message arrives, in order, with its type and payload
intact, and nothing is left in flight."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (%with-loopback-pair (client server)
      (%fuzz-transport-simulation fdp (make-insecure-random-context (consume-integral fdp :u64))
                                  (%fuzz-v1-ends client server)))))

(define-fuzz-target p2p-transport-bidirectional-v1v2
    (buffer :core "p2p_transport_serialization.cpp:397-406 (SimulationTest :107-337)"
            :iterations 30 :max-len 1500)
  "A v1 initiator talks to a responder that offers v2: the responder sniffs
the VERSION header out of whatever fragments arrive, falls back to v1, and
from then on every message either side sends arrives in order and intact."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (rng (make-insecure-random-context (consume-integral fdp :u64))))
    ;; MakeV2Transport's key, garbage length and entropy (:345-372): ours
    ;; draws its own, so the buffer's bytes are consumed and set aside.
    (consume-bytes fdp 32)
    (consume-integral-in-range fdp 0 4095)
    (consume-bytes fdp 32)
    (%with-loopback-pair (client server)
      (let* ((detected (list :pending))
             (sniffer (bt:make-thread
                       (lambda ()
                         (setf (car detected)
                               (handler-case (%v2t-detect server :timeout 25)
                                 (error (e) e))))
                       :name "fuzz-v1v2-responder"))
             (ends (%fuzz-v1-ends client server))
             (sent (vector 0 0)))
        (unwind-protect
             (setf sent (%fuzz-transport-simulation
                         fdp rng ends
                         :ready-p (lambda (side)
                                    (or (zerop side) (not (eq (car detected) :pending))))))
          ;; An initiator that never sent its VERSION header leaves Core's
          ;; responder in MAYBE_V1; ours is waiting on the socket, so hang up.
          (when (< (aref sent 0) 16)
            (bl.net:close-connection client))
          (sb-thread:join-thread sniffer :default nil :timeout 30))
        (fuzz-assert (eq (eq (fuzz-sabotage (car detected)) :v1) (>= (aref sent 0) 16))
                     "the responder answered ~S after ~D bytes of a v1 VERSION"
                     (car detected) (aref sent 0))))))
