(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/node_eviction.cpp at the pin: SelectNodeToEvict
;;;; (node/eviction.cpp:178-240) over up to 10,000 fuzzed candidates; Core
;;;; asserts the node it picks is one of them. Ours is
;;;; SELECT-INBOUND-PEER-TO-EVICT over inbound peers whose eviction features
;;;; -- address and netgroup, connection time, minimum ping, last block and
;;;; transaction times, services, whether they relay transactions to us,
;;;; whether they loaded a bloom filter, noban -- are the buffer's.
;;;;
;;;; Beyond membership the target checks what each of Core's protection
;;;; passes implies about the peer it picks. A pass protects the last K of
;;;; the remaining candidates in its order, and earlier passes only remove
;;;; candidates, so a peer is safe from eviction whenever fewer than K of ALL
;;;; candidates sort after it -- in Core's order, tie-breaks included:
;;;; minimum ping (8), CompareNodeTXTime (4), CompareNodeBlockRelayOnlyTime
;;;; among non-tx-relay peers with the services we want (8), and
;;;; CompareNodeBlockTime (4). The keyed netgroup pass depends on the
;;;; node's secret key and is not modelled; nor is the ratio pass. A noban
;;;; peer is never picked, and with more than the 28 peers the first five
;;;; passes can protect, somebody always is.

(def-suite :fuzz-node-eviction-tests :in :bitcoin-lisp-tests
  :description "Core fuzz node_eviction.cpp")

(in-suite :fuzz-node-eviction-tests)

(defun %eviction-version (relay)
  "A VERSION message as the handler stores it, with fRelay RELAY."
  (bl.bytes:with-byte-reader (in (bl.ser:make-version-message-bytes :relay relay))
    (bl.ser:read-version-message in)))

(defun %eviction-candidate (fdp rank)
  "An inbound peer with the buffer's features. RANK makes the connection time
and the minimum ping distinct, as Core's own orders need them to be total."
  (let* ((address (call-one-of fdp
                    (format nil "10.~D.~D.~D" (consume-integral-in-range fdp 0 3)
                            (consume-integral fdp :u8) (consume-integral fdp :u8))
                    (format nil "8.8.~D.~D" (consume-integral fdp :u8) (consume-integral fdp :u8))
                    (format nil "127.0.0.~D" (consume-integral-in-range fdp 1 254))
                    (format nil "192.168.0.~D" (consume-integral-in-range fdp 1 254))))
         (p (bl.net:make-peer :address address :inbound t :state :ready
                              :connect-time (+ 1000 (* 7 rank) (consume-integral-in-range fdp 0 6)))))
    (setf (bl.net:peer-inbound-onion p) (and (string= "127." address :end2 4) (consume-bool fdp))
          (bl.net:peer-min-ping-latency p) (+ 1 (* 7 (consume-integral-in-range fdp 0 100000)) (mod rank 7))
          (bl.net:peer-last-tx-time p) (pick-value-in-array fdp '(0 0 100 200))
          (bl.net:peer-last-block-time p) (pick-value-in-array fdp '(0 0 100 200))
          (bl.net:peer-services p) (pick-value-in-array fdp (list 0 (logior bl.ser:+node-network+ bl.ser:+node-witness+)
                                                                  (logior bl.ser:+node-network-limited+ bl.ser:+node-witness+)))
          (bl.net:peer-version p) (call-one-of fdp nil (%eviction-version t) (%eviction-version nil)))
    (when (consume-bool fdp)
      (setf (bl.net:peer-bloom-filter p) (bl.net:make-bloom-filter 10 0.01d0 0 0)))
    p))

(defun %eviction-relays-p (p)
  "Core's m_relay_txs: set at VERSION when the peer asked for transactions
(net_processing.cpp:3695), or by filterload/filterclear."
  (and (bl.net:peer-version p) (bl.net:peer-tx-relay-p p) t))

(defun %eviction-relevant-p (p)
  "Core's fRelevantServices: HasAllDesirableServiceFlags of its services."
  (bl.net:has-all-desirable-service-flags-p (bl.net:peer-services p) nil))

(defun %count-after (order peer candidates &optional (eligible (constantly t)))
  "How many of CANDIDATES sort strictly after PEER in ORDER (a less-than),
counting only ELIGIBLE ones."
  (count-if (lambda (c) (and (not (eq c peer)) (funcall eligible c) (funcall order peer c))) candidates))

(define-fuzz-target node-eviction
    (buffer :core "node_eviction.cpp:19-48" :iterations 500 :max-len 1500)
  "The peer picked for eviction is an inbound candidate, never a noban one,
and not one Core's ping, transaction, block-relay-only or block pass
would protect; with more than 28 evictable candidates one is always picked."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (bl.net:*whitelist-entries* (list (bl.net:parse-whitelist-entry "noban@192.168.0.0/16")))
         (candidates (loop for rank from 0
                           while (and (< rank 60) (plusp (consume-integral-in-range fdp 0 31)))
                           collect (%eviction-candidate fdp rank)))
         (evictable (remove-if (lambda (p) (bl.net:peer-has-permission-p p bl.net:+perm-noban+)) candidates))
         (victim (let ((bl:*eviction-netgroup-key* (cons 1 2)))
                   (bl:select-inbound-peer-to-evict candidates :near-tip nil))))
    (when (> (length evictable) 28)
      (fuzz-assert (fuzz-sabotage victim) "~D evictable candidates and nobody picked" (length evictable)))
    (when victim
      (fuzz-assert (member victim evictable) "the victim is not an evictable candidate")
      (flet ((connected< (a b) (> (bl.net:peer-connect-time a) (bl.net:peer-connect-time b))))
        (let ((ping< (lambda (a b) (> (bl.net:peer-min-ping-latency a) (bl.net:peer-min-ping-latency b))))
              (tx< (lambda (a b)
                     (cond ((/= (bl.net:peer-last-tx-time a) (bl.net:peer-last-tx-time b))
                            (< (bl.net:peer-last-tx-time a) (bl.net:peer-last-tx-time b)))
                           ((not (eq (%eviction-relays-p a) (%eviction-relays-p b))) (%eviction-relays-p b))
                           ((not (eq (and (bl.net:peer-bloom-filter a) t) (and (bl.net:peer-bloom-filter b) t)))
                            (and (bl.net:peer-bloom-filter a) t))
                           (t (connected< a b)))))
              (block-relay< (lambda (a b)
                              (cond ((not (eq (%eviction-relays-p a) (%eviction-relays-p b))) (%eviction-relays-p a))
                                    ((/= (bl.net:peer-last-block-time a) (bl.net:peer-last-block-time b))
                                     (< (bl.net:peer-last-block-time a) (bl.net:peer-last-block-time b)))
                                    ((not (eq (%eviction-relevant-p a) (%eviction-relevant-p b))) (%eviction-relevant-p b))
                                    (t (connected< a b)))))
              (block< (lambda (a b)
                        (cond ((/= (bl.net:peer-last-block-time a) (bl.net:peer-last-block-time b))
                               (< (bl.net:peer-last-block-time a) (bl.net:peer-last-block-time b)))
                              ((not (eq (%eviction-relevant-p a) (%eviction-relevant-p b))) (%eviction-relevant-p b))
                              (t (connected< a b))))))
          (fuzz-assert (>= (fuzz-sabotage (%count-after ping< victim evictable)) 8)
                       "evicted a peer among the 8 lowest pings")
          (fuzz-assert (>= (%count-after tx< victim evictable) 4)
                       "evicted a peer Core's transaction pass protects")
          (when (and (not (%eviction-relays-p victim)) (%eviction-relevant-p victim))
            (fuzz-assert (>= (%count-after block-relay< victim evictable) 8)
                         "evicted a block-relay-only peer Core protects"))
          (fuzz-assert (>= (%count-after block< victim evictable) 4)
                       "evicted a peer Core's block pass protects"))))))
