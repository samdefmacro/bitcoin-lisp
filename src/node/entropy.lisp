(in-package #:bitcoin-lisp)

;;;; Genesis block headers
;;; Genesis parameters from Bitcoin Core chainparams.cpp

;;;; Process entropy

(defconstant +random-seed-bytes+ 32
  "Bytes of OS entropy folded into the process CL:*RANDOM-STATE* seed.
Matches the 256-bit seed Core's FastRandomContext takes from GetRandHash().")

(defvar *random-state-seed* nil
  "The integer seed most recently installed into CL:*RANDOM-STATE* by
SEED-GLOBAL-RANDOM-STATE, NIL while the process is still running on SBCL's
build-time state. Recorded so startup (and a test) can tell 'seeded' from
'never seeded' — the two are indistinguishable by looking at draws.")

(defun %os-entropy-seed ()
  "+RANDOM-SEED-BYTES+ bytes from the OS CSPRNG as a positive integer.
IRONCLAD:*PRNG* is the OS PRNG (getrandom(2) / /dev/urandom), so two processes
started a microsecond apart get unrelated seeds. Falls back to a clock-derived
mix only if the OS source is unreachable: much weaker, but still not the
build-time constant, which is the property that matters here."
  (handler-case
      (ironclad:octets-to-integer (ironclad:random-data +random-seed-bytes+))
    (error (e)
      (log-warn "OS entropy source unavailable (~A); seeding the RNG from the clock" e)
      ;; SBCL's (make-random-state t) mixes sub-second time, so two starts in
      ;; the same second still diverge; the wall clock widens the seed.
      (logxor (random (expt 2 62) (make-random-state t))
              (ash (get-universal-time) 32)))))

(defun seed-global-random-state ()
  "Replace the process-global CL:*RANDOM-STATE* with one seeded from OS
entropy; return the seed.

SBCL's *random-state* is part of the saved core: it is IDENTICAL in every fresh
image (verified on 2.6.5 — `(random 1000000)` is 113500 on the first draw of
every run), because SBCL seeds it at build time rather than from the OS. A node
that never re-seeds therefore replays one fixed sequence on every start, and
every draw whose entire value is unpredictability becomes a stable fingerprint:
addr-relay Poisson timers and the initial-broadcast jitter
(networking/protocol.lisp), addrman's new/tried selection and its GetAddr
shuffle (networking/addrman.lisp), the sendtxrcncl salt and ping nonces
(networking/peer.lisp), the VERSION nonce (serialization/messages.lisp). Core
draws all of these from OS-seeded contexts — FastRandomContext (net.cpp:3728,
random.h:394) and PeerManagerImpl::m_rng (net_processing.cpp:2009), which is
deterministic only under the test-only `deterministic_rng` option.

Assigns the GLOBAL value deliberately: SBCL threads read the global binding of
*random-state* (they do not inherit the starter thread's dynamic bindings), and
the peers that draw the jitter above run on their own threads. Tests that need
a reproducible stream bind *random-state* around their own code — the
assignment then lands on that binding and leaves the global alone."
  (let ((seed (%os-entropy-seed)))
    (setf *random-state* (sb-ext:seed-random-state seed)
          *random-state-seed* seed)
    ;; Never log the seed itself: it predicts every subsequent draw. (The
    ;; message stays source-neutral — the fallback above logs its own warning.)
    (log-debug "Seeded *random-state* with a ~D-byte seed" +random-seed-bytes+)
    seed))
