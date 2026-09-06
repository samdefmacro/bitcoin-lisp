(in-package #:bitcoin-lisp.tests)

;;;; Process entropy: CL:*RANDOM-STATE* seeding at node startup (GA8 W3).
;;;;
;;;; SBCL's *random-state* lives in the saved core, seeded at BUILD time rather
;;;; than from the OS, so every fresh image replays one fixed sequence: on
;;;; SBCL 2.6.5 the first `(random 1000000)` of every process is 113500. Bare
;;;; `(random n)` therefore produces an identical stream on every node start,
;;;; and everything we draw from it whose whole value is unpredictability —
;;;; addr-relay Poisson timers, initial-broadcast jitter, addrman bucket
;;;; selection and the GetAddr shuffle, the getaddr-cache expiry jitter and the
;;;; feefilter delays — becomes a stable cross-restart fingerprint. Core draws
;;;; these from OS-seeded contexts: FastRandomContext (random.h:394,
;;;; net.cpp:3728) and PeerManagerImpl::m_rng (net_processing.cpp:2009),
;;;; deterministic only under the test-only `deterministic_rng` option.
;;;;
;;;; Seeding is the weaker guarantee, and the values we PUBLISH do not rely on
;;;; it: the ping, VERSION and compact-block nonces and the BIP330 salt come
;;;; off the OS CSPRNG through BL.CRYPTO:RAND-U64, because MT19937 is
;;;; invertible from its own output and publishing a draw would expose the
;;;; stream that picks which address we dial next (GA11 4a05974e). Those draws
;;;; are asserted in the crypto and P2P suites; this file covers the stream
;;;; that stays.
;;;;
;;;; These tests pin down that the seeding actually RUNS, not merely that two
;;;; draws differ (which any PRNG satisfies): SEED-GLOBAL-RANDOM-STATE records
;;;; the integer seed it installed, so "seeded" is distinguishable from "never
;;;; seeded", and the assertions compare against the exact stream that was in
;;;; place before the call.

(def-suite :entropy-tests
  :description "Process RNG seeding: *random-state* must not replay SBCL's build-time stream"
  :in :bitcoin-lisp-tests)

(in-suite :entropy-tests)

(defun %entropy-draws (n &optional (state *random-state*))
  "N draws from STATE, as a list (advances STATE)."
  (loop repeat n collect (random 1000000 state)))

(test seed-global-random-state-installs-os-entropy
  "SEED-GLOBAL-RANDOM-STATE replaces *random-state* with a state seeded from
+random-seed-bytes+ bytes of OS entropy, and records the seed. Compared against
the exact stream that was installed beforehand, so an unseeded process is
distinguishable from a seeded one."
  (let* ((before (sb-ext:seed-random-state 20260726))
         ;; What the stream WOULD have produced had the seeding not run.
         (would-have (%entropy-draws 8 (sb-ext:seed-random-state 20260726)))
         (bl::*random-state-seed* nil)
         (*random-state* before)
         (seed (bl::seed-global-random-state)))
    ;; The seeding ran and left evidence: a recorded integer seed.
    (is-true (integerp bl::*random-state-seed*)
             "*random-state-seed* is ~S, so the seeding never ran"
             bl::*random-state-seed*)
    (is (eql seed bl::*random-state-seed*))
    ;; 32 bytes off the CSPRNG: a value under 2^192 has probability 2^-64.
    (is-true (> (integer-length seed) 192)
             "seed has only ~D bits; a 32-byte OS draw was expected"
             (integer-length seed))
    ;; The old state object is gone, and so is its stream.
    (is-false (eq *random-state* before))
    (is (not (equal would-have (%entropy-draws 8))))))

(test seed-global-random-state-differs-per-process
  "Two independently seeded nodes must not share a stream. Two re-seeds in one
image is the same operation two fresh starts perform (each start's seed comes
from the OS CSPRNG, never from the previous state)."
  (let* ((bl::*random-state-seed* nil)
         (*random-state* (sb-ext:seed-random-state 1))
         (seed-a (bl::seed-global-random-state))
         (draws-a (%entropy-draws 8))
         (seed-b (bl::seed-global-random-state))
         (draws-b (%entropy-draws 8)))
    (is (/= seed-a seed-b))
    (is (not (equal draws-a draws-b)))))

(test seeded-random-state-stream-is-uniform
  "Statistical smoke test on the seeded stream: 4096 byte draws cover nearly
the whole range with a mean near 127.5. Catches a seeding that installs a
degenerate state (all-zero key, constant output) rather than a working one.
Tolerances are ~13 sigma, so this does not flake."
  (let* ((bl::*random-state-seed* nil)
         (*random-state* (sb-ext:seed-random-state 7))
         (n 4096))
    (bl::seed-global-random-state)
    (let ((seen (make-array 256 :element-type 'bit :initial-element 0))
          (total 0))
      (dotimes (i n)
        (let ((b (random 256)))
          (setf (sbit seen b) 1)
          (incf total b)))
      (let ((distinct (count 1 seen))
            (mean (/ total (float n))))
        (is-true (>= distinct 240) "only ~D distinct byte values in ~D draws" distinct n)
        (is-true (< 110.0 mean 145.0) "mean of ~D draws was ~,2F" n mean)))))

(test init-node-seeds-the-process-rng
  "The production wiring: INIT-NODE — the head of the only startup path, run
before start-node builds the address book or dials anything — re-seeds the
process RNG and draws the inbound-eviction netgroup key. Without the first
call the node runs on SBCL's build-time stream; without the second the
netgroup key stays NIL and inbound eviction signals (GA11 6c83742d). Core does
both at AppInitMain, the netgroup seeds as CConnman's first two constructor
arguments (init.cpp:1642-1648)."
  (let ((dir (merge-pathnames "test-entropy-init/" (uiop:temporary-directory))))
    (unwind-protect
         ;; init-node also assigns the network globals; bind them so this test
         ;; hands the suite back exactly the environment it found.
         (let* ((bl:*network* bl:*network*)
                (bl.store:*pow-limit-target* bl.store:*pow-limit-target*)
                (bl.ser:*network-magic* bl.ser:*network-magic*)
                (bl.net:*current-port* bl.net:*current-port*)
                (bl.net:*dns-seeds* bl.net:*dns-seeds*)
                (bl::*random-state-seed* nil)
                (bl::*eviction-netgroup-key* nil)
                (would-have (%entropy-draws 8 (sb-ext:seed-random-state 424242)))
                (*random-state* (sb-ext:seed-random-state 424242))
                (node (bl::init-node dir :network :regtest)))
           (is-true (bl:node-p node))
           (is-true (integerp bl::*random-state-seed*)
                    "init-node left *random-state-seed* ~S: it never seeded the RNG"
                    bl::*random-state-seed*)
           (is (not (equal would-have (%entropy-draws 8))))
           (is-true (consp bl::*eviction-netgroup-key*)
                    "init-node left the eviction netgroup key ~S: it never drew one"
                    bl::*eviction-netgroup-key*))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test seeded-random-state-reaches-worker-threads
  "The seeding assigns the GLOBAL value of *random-state*, which is what a
freshly started thread reads (dynamic bindings do not cross MAKE-THREAD). The
peer threads that draw the relay jitter are such threads, so a seeding visible
only to the starter thread would fix nothing."
  (let ((saved-state (sb-ext:symbol-global-value 'cl:*random-state*))
        (saved-seed bl::*random-state-seed*))
    (unwind-protect
         (progn
           ;; Deliberately NOT a dynamic binding: seed-global-random-state must
           ;; reach the global, so the pre-state has to be global too.
           (setf (sb-ext:symbol-global-value 'cl:*random-state*)
                 (sb-ext:seed-random-state 4242))
           (let ((would-have (%entropy-draws 4 (sb-ext:seed-random-state 4242))))
             (bl::seed-global-random-state)
             (let ((from-thread :thread-never-ran))
               (bt:join-thread
                (bt:make-thread (lambda () (setf from-thread (%entropy-draws 4)))
                                :name "entropy-test-worker"))
               (is (not (eq from-thread :thread-never-ran)))
               (is (not (equal would-have from-thread))))))
      (setf (sb-ext:symbol-global-value 'cl:*random-state*) saved-state
            bl::*random-state-seed* saved-seed))))
