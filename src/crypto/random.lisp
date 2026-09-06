(in-package #:bitcoin-lisp.crypto)

;;;; OS randomness (Core src/random.h, src/random.cpp)
;;;
;;; Core draws everything an adversary either SEES (a VERSION or ping nonce, a
;;; BIP330 salt, a compact-block nonce) or must not PREDICT (the keyed-netgroup
;;; seeds, addrman selection) from a FastRandomContext -- ChaCha20 keyed from
;;; the operating system's entropy source -- and never from a linear generator.
;;;
;;; CL:RANDOM cannot stand in for that. SBCL's *random-state* is MT19937: its
;;; 19937-bit state is recoverable in closed form from 624 consecutive tempered
;;; outputs and can be run backwards as well as forwards, so a peer that
;;; collects enough published nonces learns every other draw of the same
;;; stream. It is also not thread-safe, and the state a fresh image starts with
;;; is fixed at SBCL BUILD time -- so a value drawn during ASDF load (a DEFVAR
;;; initform, say) is the same number in every process, on every machine, for
;;; everyone running that SBCL.
;;;
;;; This file is the one place that reaches the OS source, so a call site can
;;; be read as "public or secret -> RAND-U64" without repeating the ironclad
;;; incantation. Draws whose only job is to spread work in time (relay jitter,
;;; Poisson timers, 1-in-3 tie-breaks) stay on CL:RANDOM: they publish nothing
;;; and predicting them buys an attacker nothing that the timing of our
;;; messages does not already show. SEED-GLOBAL-RANDOM-STATE (src/node/
;;; entropy.lisp) keeps that stream off the build-time sequence.

(defun rand-u64 ()
  "A fresh 64-bit unsigned integer from the OS CSPRNG (Core GetRand<uint64_t>
/ FastRandomContext::rand64, random.h).

IRONCLAD:*PRNG* is the OS PRNG: getrandom(2), falling back to /dev/urandom.
Deliberately has NO fallback of its own -- a node that cannot reach the
system entropy source must fail loudly rather than quietly hand out nonces
and keys from a weaker source."
  (let ((bytes (ironclad:random-data 8)))
    (loop for i from 0 below 8
          for shift from 0 by 8
          sum (ash (aref bytes i) shift))))
