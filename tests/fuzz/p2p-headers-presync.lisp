(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/p2p_headers_presync.cpp at the pin: low-work headers,
;;;; compact blocks and blocks from three peers (outbound full-relay,
;;;; block-relay, inbound), none of which may ever enter the block index --
;;;; the chain they build has less work than the anti-DoS threshold, so the
;;;; headers belong to the low-work pre-sync (Core HeadersSyncState) and
;;;; nowhere else.
;;;;
;;;; Core runs on mainnet with its fuzz build's shortcut proof of work. Ours
;;;; runs on regtest, whose target a header meets in two tries, with the
;;;; minimum chain work (*MINIMUM-CHAIN-WORK-OVERRIDE*, -minimumchainwork) far
;;;; above anything a buffer can build -- the same situation, reachable
;;;; without a shortcut. Core's batches are capped at 16 by a test-only
;;;; option; ours hold 16 headers, or one draw in six a full 2,000
;;;; (MAX_HEADERS_RESULTS), since a full batch is what keeps a pre-sync going.

(def-suite :fuzz-p2p-headers-presync-tests :in :bitcoin-lisp-tests
  :description "Core fuzz p2p_headers_presync.cpp over our low-work headers sync")

(in-suite :fuzz-p2p-headers-presync-tests)

(defun %presync-header (fdp prev-hash prev-bits prev-time)
  "Core ConsumeHeader + FinalizeHeader on regtest: the parent's nBits or a
fuzzed easier-than-regtest one, a time near the parent's, a fuzzed version,
ground to meet its target."
  (grind-header-pow
   (bl.ser:make-block-header
    :version (consume-integral fdp :i32)
    :prev-block prev-hash
    :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
    :timestamp (min #xffffffff (+ prev-time (consume-integral-in-range fdp 0 1200)))
    :bits (if (consume-bool fdp) prev-bits (pick-value-in-array fdp '(#x207fffff #x207ffffe #x2070ffff)))
    :nonce 0)))

(defun %presync-block (fdp prev-hash prev-bits prev-time)
  "Core ConsumeBlock: a header on the base with one transaction whose txid is
its merkle root, so it passes the mutation checks."
  (let* ((tx (bl.ser:make-transaction
              :version 1 :lock-time 0
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                                 :index 0)
                               :script-sig (make-array 2 :element-type '(unsigned-byte 8) :initial-element 0)
                               :sequence 0))
              :outputs (vector (bl.ser:make-tx-out :value 0 :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))))
         (header (%presync-header fdp prev-hash prev-bits prev-time)))
    (setf (bl.ser:block-header-merkle-root header) (bl.ser:transaction-hash tx)
          (bl.ser:block-header-cached-hash header) nil)
    (bl.ser:make-bitcoin-block :header (grind-header-pow header) :transactions (list tx))))

(define-fuzz-target p2p-headers-presync
    (buffer :core "p2p_headers_presync.cpp:165-250" :iterations 25 :max-len 600)
  "Headers, compact blocks and blocks of a chain with less than the minimum
chain work, from any of three peers, leave the block index exactly as it
was."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-p2p-node (p2p)
      (let* ((bl:*minimum-chain-work-override* (ash 1 200))
             (cs (bl:node-chain-state (fp-node p2p)))
             (index-size (hash-table-count (bl.store:chain-state-block-index cs)))
             (genesis (bl.store:get-block-index-entry cs (bl.store:chain-state-genesis-hash cs)))
             (base-hash (bl.store:block-index-entry-hash genesis))
             (base-header (bl.store:block-index-entry-header genesis))
             (base-bits (bl.ser:block-header-bits base-header))
             (base-time (bl.ser:block-header-timestamp base-header))
             (peers (loop for conn-type in '(:outbound-full-relay :block-relay :inbound)
                          for id from 1
                          collect (bl.net:make-peer
                                   :id id :state :ready :address "127.0.0.1"
                                   :connection (make-test-connection :host "127.0.0.1" :port (+ 18444 id) :connected t)
                                   :services #x409 :conn-type conn-type
                                   :inbound (eq conn-type :inbound)))))
        (setf (bl.ctx:node-context-peers (fp-ctx p2p)) peers)
        (limited-while ((plusp (consume-integral-in-range fdp 0 7)) 100)
          (let ((peer (pick-value-in-array fdp peers)))
            (call-one-of fdp
              (let ((headers (loop repeat (if (zerop (consume-integral-in-range fdp 0 5)) 2000 16)
                                   collect (let ((h (%presync-header fdp base-hash base-bits base-time)))
                                             (setf base-hash (bl.ser:block-header-hash h)
                                                   base-bits (bl.ser:block-header-bits h)
                                                   base-time (bl.ser:block-header-timestamp h))
                                             h))))
                (%fuzz-deliver p2p peer "headers" (%payload (bl.ser:make-headers-message headers))))
              (%fuzz-deliver p2p peer "cmpctblock"
                             (%payload (bl.ser:make-cmpctblock-message
                                        (%presync-block fdp base-hash base-bits base-time)
                                        :nonce (consume-integral fdp :u64))))
              (%fuzz-deliver p2p peer "block"
                             (%payload (bl.ser:make-block-message
                                        (%presync-block fdp base-hash base-bits base-time)))))
            (fuzz-assert (= (fuzz-sabotage (hash-table-count (bl.store:chain-state-block-index cs))) index-size)
                         "the block index grew from ~D to ~D entries on a low-work chain"
                         index-size (hash-table-count (bl.store:chain-state-block-index cs)))))))))
