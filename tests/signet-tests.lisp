;;;; BIP325 signet block-solution validation tests (port checks vs Core signet.cpp).

(in-package #:bitcoin-lisp.tests)

(def-suite :signet-tests :in :bitcoin-lisp-tests)
(in-suite :signet-tests)

(defun %sig-bv (&rest bs)
  (make-array (length bs) :element-type '(unsigned-byte 8) :initial-contents bs))

(defun %sig-fill (n val)
  (make-array n :element-type '(unsigned-byte 8) :initial-element val))

(defun %sig-cat (&rest chunks)
  (apply #'concatenate '(vector (unsigned-byte 8)) chunks))

(defun %sig-witness-commitment (segwit-hash32 &optional signet-payload)
  "A coinbase witness-commitment scriptPubKey: OP_RETURN PUSH36(0xaa21a9ed||hash)
optionally followed by a minimal push of SIGNET-PAYLOAD (which already includes
the 4-byte SIGNET_HEADER when present)."
  (let ((base (%sig-cat (%sig-bv #x6a #x24 #xaa #x21 #xa9 #xed) segwit-hash32)))
    (if signet-payload
        (%sig-cat base (bitcoin-lisp.validation::%minimal-push signet-payload))
        base)))

(defun %sig-coinbase (commitment-script)
  "A minimal coinbase-shaped tx whose LAST output carries COMMITMENT-SCRIPT."
  (bitcoin-lisp.serialization:make-transaction
   :version 1 :lock-time 0
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash (%sig-fill 32 0) :index #xffffffff)
                    :script-sig (%sig-bv #x51) :sequence #xffffffff))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value 5000000000 :script-pubkey (%sig-bv #x51))
                    (bitcoin-lisp.serialization:make-tx-out
                     :value 0 :script-pubkey commitment-script))))

(defun %sig-block (coinbase)
  (bitcoin-lisp.serialization:make-bitcoin-block
   :header (bitcoin-lisp.serialization:make-block-header
            :version 536870912
            :prev-block (%sig-fill 32 3)
            :merkle-root (%sig-fill 32 0)
            :timestamp 1600000000 :bits #x1d00ffff :nonce 0)
   :transactions (list coinbase)))

(defun %sig-serialize-solution (script-sig-content witness-list)
  "Serialize a signet solution: scriptSig (CScript) then the witness stack,
matching Core's SpanReader >> scriptSig >> scriptWitness.stack."
  (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
    (bitcoin-lisp.serialization::write-var-bytes s script-sig-content)
    (bitcoin-lisp.serialization::write-witness-stack s witness-list)))

(defparameter +sig-dummy-genesis+ (%sig-fill 32 #xff)
  "A genesis hash that no test block matches, so the genesis short-circuit stays
out of the way except where explicitly exercised.")

(test signet-genesis-trivially-valid
  "A block whose hash equals the (passed) signet genesis hash is valid without
any solution check -- Core's genesis short-circuit."
  (let* ((cb (%sig-coinbase (%sig-witness-commitment (%sig-fill 32 0))))
         (blk (%sig-block cb))
         (h (bitcoin-lisp.serialization:block-header-hash
             (bitcoin-lisp.serialization:bitcoin-block-header blk))))
    (is-true (bitcoin-lisp.validation:check-signet-block-solution blk (%sig-bv #x51) h))))

(test signet-optrue-challenge-valid
  "A trivial OP_TRUE challenge with no signet solution verifies: SignetTxs are
built and the empty scriptSig satisfies OP_TRUE (Core allows this)."
  (let* ((cb (%sig-coinbase (%sig-witness-commitment (%sig-fill 32 0))))
         (blk (%sig-block cb)))
    (is-true (bitcoin-lisp.validation:check-signet-block-solution
              blk (%sig-bv #x51) +sig-dummy-genesis+))))

(test signet-no-witness-commitment-rejected
  "No witness-commitment output in the coinbase -> SignetTxs::Create fails -> invalid."
  (let* ((cb (%sig-coinbase (%sig-bv #x6a #x00)))   ; bare OP_RETURN, not a commitment
         (blk (%sig-block cb)))
    (is-false (bitcoin-lisp.validation:check-signet-block-solution
               blk (%sig-bv #x51) +sig-dummy-genesis+))))

(test signet-extraneous-solution-data-rejected
  "A signet solution with trailing bytes fails to parse -> invalid (Core: 'extraneous
data encountered')."
  (let* ((payload (%sig-cat bitcoin-lisp.validation::*signet-header*
                            (%sig-bv #x01 #xab   ; scriptSig: push 1 byte 0xab
                                     #x00        ; witness stack: 0 items
                                     #xff)))      ; trailing junk
         (cb (%sig-coinbase (%sig-witness-commitment (%sig-fill 32 0) payload)))
         (blk (%sig-block cb)))
    (is-false (bitcoin-lisp.validation:check-signet-block-solution
               blk (%sig-bv #x51) +sig-dummy-genesis+))))

(test signet-challenge-for-network
  "signet-challenge-for-network returns the challenge only for :signet."
  (is (equalp bitcoin-lisp.validation:*default-signet-challenge*
              (bitcoin-lisp.validation:signet-challenge-for-network :signet)))
  (is (null (bitcoin-lisp.validation:signet-challenge-for-network :mainnet)))
  (is (null (bitcoin-lisp.validation:signet-challenge-for-network :testnet4))))

(test signet-checksig-solution-roundtrip
  "End-to-end: with a single-key <pubkey> OP_CHECKSIG challenge, produce a real
signet solution by signing block_data over the modified block, embed it, and
verify it is accepted -- then tamper the signature and verify rejection. This
exercises block_data serialization, the modified merkle root, solution embed/
parse/clear, and the legacy sighash all lining up."
  (let* ((privkey (let ((k (%sig-fill 32 0))) (setf (aref k 31) 1) k))
         (pubkey (bitcoin-lisp.crypto:derive-public-key privkey))         ; 33-byte compressed
         (challenge (%sig-cat (%sig-bv #x21) pubkey (%sig-bv #xac)))       ; PUSH33 <pk> OP_CHECKSIG
         ;; Coinbase carrying the empty 4-byte SIGNET_HEADER push (size == 4,
         ;; so fetch-and-clear does NOT treat it as a solution): the state the
         ;; miner signs over.
         (cb0 (%sig-coinbase (%sig-witness-commitment
                              (%sig-fill 32 0) bitcoin-lisp.validation::*signet-header*)))
         (block0 (%sig-block cb0)))
    (multiple-value-bind (to-spend to-sign)
        (bitcoin-lisp.validation:make-signet-txs block0 challenge)
      (declare (ignore to-spend))
      (is-true to-sign)
      (let* ((sighash (bitcoin-lisp.coalton.interop::compute-legacy-sighash
                       to-sign 0 challenge #x01))                          ; SIGHASH_ALL
             (der (bitcoin-lisp.crypto:sign-ecdsa privkey sighash))
             (full-sig (%sig-cat der (%sig-bv #x01)))                      ; DER || SIGHASH_ALL
             (script-sig (bitcoin-lisp.validation::%minimal-push full-sig))
             (solution (%sig-serialize-solution script-sig '()))
             (payload (%sig-cat bitcoin-lisp.validation::*signet-header* solution))
             (cb1 (%sig-coinbase (%sig-witness-commitment (%sig-fill 32 0) payload)))
             (block1 (%sig-block cb1)))
        ;; valid solution accepted
        (is-true (bitcoin-lisp.validation:check-signet-block-solution
                  block1 challenge +sig-dummy-genesis+))
        ;; tampered signature rejected
        (let* ((bad (copy-seq full-sig)))
          (setf (aref bad 10) (logxor (aref bad 10) #x01))
          (let* ((bad-ss (bitcoin-lisp.validation::%minimal-push bad))
                 (bad-sol (%sig-serialize-solution bad-ss '()))
                 (bad-payload (%sig-cat bitcoin-lisp.validation::*signet-header* bad-sol))
                 (bad-cb (%sig-coinbase (%sig-witness-commitment (%sig-fill 32 0) bad-payload)))
                 (bad-block (%sig-block bad-cb)))
            (is-false (bitcoin-lisp.validation:check-signet-block-solution
                       bad-block challenge +sig-dummy-genesis+))))))))

;;;; ==================================================================
;;;; GA9 S2-1: signet could not follow its own chain
;;;;
;;;; Two independent defects, both "we reject what Core accepts", together
;;;; meaning the node could not advance past height 1 on signet. This file
;;;; previously covered only the BIP325 solution port and never ran a signet
;;;; header through difficulty or PoW validation at all, which is how a whole
;;;; network stayed broken while looking tested.

(test ga9-s2-1-signet-pow-limit-accepts-signet-nbits
  "Core's signet powLimit is 00000377ae...00 (kernel/chainparams.cpp:490),
which is EASIER than mainnet's minimum. *pow-limit-target* was raised only for
regtest, so signet ran against the MAINNET limit and derive-target rejected
every real signet nBits — including signet's own genesis 0x1e0377ae, a value
this tree already records in chain.lisp."
  (is (string= "00000377ae000000000000000000000000000000000000000000000000000000"
               (string-downcase
                (format nil "~64,'0x" bitcoin-lisp.storage:+signet-pow-limit-target+)))
      "the constant must be Core's powLimit byte for byte")
  (let ((bitcoin-lisp.storage:*pow-limit-target*
          bitcoin-lisp.storage:+signet-pow-limit-target+))
    (is-true (bitcoin-lisp.storage:derive-target #x1e0377ae)
             "signet's genesis nBits must derive a target under signet's limit"))
  ;; The control that makes this test mean something: the SAME nBits is
  ;; rejected under the mainnet limit, which is what the node used to do.
  (let ((bitcoin-lisp.storage:*pow-limit-target*
          bitcoin-lisp.storage:+pow-limit-target+))
    (is-false (bitcoin-lisp.storage:derive-target #x1e0377ae)
              "control: under the mainnet limit it is rejected — the bug")))

(test ga9-s2-1-signet-inherits-bits-at-a-non-boundary
  "Signet sets fPowAllowMinDifficultyBlocks = false (chainparams.cpp:491), so
Core's GetNextWorkRequired simply returns pindexLast->nBits at a non-boundary
height (pow.cpp:38) — exactly as for mainnet.

get-expected-bits had an arm for :mainnet and then fell through to NIL;
validate-difficulty routes a NIL expectation into the testnet min-difficulty
branch, which tests only :testnet3/:testnet4, so signet reached the terminal
reject and 2015 of every 2016 blocks failed :bad-difficulty."
  (let* ((bits #x1e0377ae)
         (prev-header (bitcoin-lisp.serialization:make-block-header
                       :version 4
                       :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element 0)
                       :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)
                       :timestamp 1600000000 :bits bits :nonce 0))
         (prev-entry (bitcoin-lisp.storage:make-block-index-entry
                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 7)
                      :height 100 :header prev-header :chain-work 1 :status :valid)))
    (let ((bitcoin-lisp:*network* :signet))
      (is (= bits (bitcoin-lisp.validation::get-expected-bits 101 prev-entry))
          "signet must inherit the previous block's bits at a non-boundary"))
    ;; Unchanged for the networks that DO allow min-difficulty blocks: they
    ;; must still get NIL so validate-difficulty takes the timestamp branch.
    (dolist (net '(:testnet3 :testnet4))
      (let ((bitcoin-lisp:*network* net))
        (is-false (bitcoin-lisp.validation::get-expected-bits 101 prev-entry)
                  "~A must still defer to the min-difficulty branch" net)))
    ;; And mainnet keeps inheriting, as before.
    (let ((bitcoin-lisp:*network* :mainnet))
      (is (= bits (bitcoin-lisp.validation::get-expected-bits 101 prev-entry))))))
