;;;; Socket readiness that survives a large file-descriptor number.
;;;;
;;;; usocket:wait-for-input goes through select(2) on SBCL. select's fd_set is
;;;; a fixed 1024-bit bitmap, so SBCL type-checks the descriptor as
;;;; (unsigned-byte 10) and a socket on fd >= 1024 SIGNALS instead of being
;;;; waited on. poll(2) takes an array of descriptors and has no such ceiling.
;;;;
;;;; This is not a hypothetical limit. On 2026-08-17/18 the mainnet node held
;;;; ~3100 open LevelDB table files, so every new socket was allocated above
;;;; the ceiling and every connection died at its first read with
;;;;
;;;;   The value 3122 is not of type (UNSIGNED-BYTE 10)
;;;;
;;;; -- the failing value is always fd+1 -- until the node sat at zero peers,
;;;; which is an eclipse reached from the inside. Bitcoin Core names the same
;;;; hazard in dbwrapper.cpp: large open-file counts are safe on Windows
;;;; "because the handles do not interfere with select() loops".
;;;;
;;;; The open-file count was fixed separately (coins-view.lisp). This file is
;;;; the second half: the ceiling should not exist at all, so that the next
;;;; subsystem to hold a few thousand descriptors cannot silently take the
;;;; network down with it.

(in-package #:bitcoin-lisp.networking)

(defun %socket-fd (socket)
  "SOCKET's underlying file descriptor, or NIL if it cannot be reached.
Accepts the usocket wrappers we actually pass around (stream and server
sockets); anything else yields NIL and the caller falls back."
  (ignore-errors
   (let ((raw (usocket:socket socket)))
     #+sbcl (when (typep raw 'sb-bsd-sockets:socket)
              (sb-bsd-sockets:socket-file-descriptor raw))
     #-sbcl (declare (ignore raw)))))

(defun socket-input-ready-p (socket &key (timeout 0))
  "T when SOCKET has input readable within TIMEOUT seconds (0 = poll once).

Replaces usocket:wait-for-input for readability checks. See the file header:
wait-for-input cannot express a descriptor at or above 1024 and signals a
TYPE-ERROR instead, which surfaces as every peer appearing to hang up at once.

Falls back to usocket:wait-for-input when the descriptor cannot be reached, so
a socket type we do not recognise still behaves as before rather than silently
reporting `never ready' -- which would be worse than the bug this replaces."
  (let ((fd (%socket-fd socket)))
    (if fd
        (let ((msec (if (or (null timeout) (zerop timeout))
                        0
                        (max 1 (round (* 1000 timeout))))))
          #+sbcl (and (sb-unix:unix-simple-poll fd :input msec) t)
          #-sbcl (and (usocket:wait-for-input socket :timeout timeout :ready-only t) t))
        (and (usocket:wait-for-input socket :timeout timeout :ready-only t) t))))
