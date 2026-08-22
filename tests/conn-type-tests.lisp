(in-package #:bitcoin-lisp.tests)

(def-suite :conn-type-tests
  :description "Connection types: block-relay-only and feeler tx-relay gating"
  :in :bitcoin-lisp-tests)

(in-suite :conn-type-tests)

(test peer-conn-type-defaults
  "A freshly-made peer defaults to :inbound; make-inbound-peer keeps it."
  (let ((p (bitcoin-lisp.networking:make-peer)))
    (is (eq :inbound (bitcoin-lisp.networking:peer-conn-type p))))
  (let ((ip (bitcoin-lisp.networking:make-inbound-peer nil "203.0.113.7")))
    (is (eq :inbound (bitcoin-lisp.networking:peer-conn-type ip)))
    (is (bitcoin-lisp.networking:peer-inbound ip))))

(test peer-relays-txs-p-by-conn-type
  "Full-relay and inbound peers relay txs; block-relay and feeler peers do not."
  (flet ((relays (type)
           (let ((p (bitcoin-lisp.networking:make-peer :conn-type type)))
             (bitcoin-lisp.networking:peer-relays-txs-p p))))
    (is-true (relays :inbound))
    (is-true (relays :outbound-full-relay))
    (is-false (relays :block-relay))
    (is-false (relays :feeler))))

(test version-relay-flag-serializes
  "The version payload's trailing relay byte is 0 for a block-relay/feeler
connection (relay nil) and 1 for a full-relay connection (relay t)."
  (let ((full (bitcoin-lisp.serialization:make-version-message-bytes :relay t))
        (none (bitcoin-lisp.serialization:make-version-message-bytes :relay nil)))
    (is (= 1 (aref full (1- (length full)))))
    (is (= 0 (aref none (1- (length none)))))))

(test version-gates-follow-core
  "Core's two VERSION-time gates (net_processing.cpp:3611-3627): an automatic
outbound peer must offer the desirable services — NODE_NETWORK|NODE_WITNESS, or
NODE_NETWORK_LIMITED|NODE_WITNESS once we are near the tip
(GetDesirableServiceFlags :1759-1768) — and every peer must announce at least
MIN_PEER_PROTO_VERSION. Inbound, manual and feeler connections are exempt from
the services gate (CNode::ExpectServicesFromConn)."
  (let ((full (logior bitcoin-lisp.serialization:+node-network+
                      bitcoin-lisp.serialization:+node-witness+))
        (limited (logior bitcoin-lisp.serialization:+node-network-limited+
                         bitcoin-lisp.serialization:+node-witness+)))
    (is (= 31800 bitcoin-lisp.networking::+min-peer-proto-version+))
    (is-true (bitcoin-lisp.networking::has-all-desirable-service-flags-p full nil))
    (is-false (bitcoin-lisp.networking::has-all-desirable-service-flags-p 0 nil))
    (is-false (bitcoin-lisp.networking::has-all-desirable-service-flags-p
               bitcoin-lisp.serialization:+node-network+ nil))   ; no witness
    ;; A limited peer is desirable only near the tip.
    (is-false (bitcoin-lisp.networking::has-all-desirable-service-flags-p limited nil))
    (is-true (bitcoin-lisp.networking::has-all-desirable-service-flags-p limited t))
    (flet ((expects (&rest args)
             (bitcoin-lisp.networking::peer-outbound-or-block-relay-p
              (apply #'bitcoin-lisp.networking:make-peer args))))
      (is-true (expects :conn-type :outbound-full-relay))
      (is-true (expects :conn-type :block-relay))
      (is-false (expects :conn-type :outbound-full-relay :manual t))
      (is-false (expects :conn-type :feeler))
      (is-false (expects :conn-type :inbound)))))
