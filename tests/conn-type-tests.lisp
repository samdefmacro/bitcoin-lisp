(in-package #:bitcoin-lisp.tests)

(def-suite :conn-type-tests
  :description "Connection types: block-relay-only and feeler tx-relay gating"
  :in :bitcoin-lisp-tests)

(in-suite :conn-type-tests)

(test peer-conn-type-defaults
  "A freshly-made peer defaults to :inbound; make-inbound-peer keeps it."
  (let ((p (bl.net:make-peer)))
    (is (eq :inbound (bl.net:peer-conn-type p))))
  (let ((ip (bl.net:make-inbound-peer nil "203.0.113.7")))
    (is (eq :inbound (bl.net:peer-conn-type ip)))
    (is (bl.net:peer-inbound ip))))

(test peer-relays-txs-p-by-conn-type
  "Full-relay and inbound peers relay txs; block-relay and feeler peers do not."
  (flet ((relays (type)
           (let ((p (bl.net:make-peer :conn-type type)))
             (bl.net:peer-relays-txs-p p))))
    (is-true (relays :inbound))
    (is-true (relays :outbound-full-relay))
    (is-false (relays :block-relay))
    (is-false (relays :feeler))))

(test version-relay-flag-serializes
  "The version payload's trailing relay byte is 0 for a block-relay/feeler
connection (relay nil) and 1 for a full-relay connection (relay t)."
  (let ((full (bl.ser:make-version-message-bytes :relay t))
        (none (bl.ser:make-version-message-bytes :relay nil)))
    (is (= 1 (aref full (1- (length full)))))
    (is (= 0 (aref none (1- (length none)))))))

(test version-gates-follow-core
  "Core's two VERSION-time gates (net_processing.cpp:3611-3627): an automatic
outbound peer must offer the desirable services — NODE_NETWORK|NODE_WITNESS, or
NODE_NETWORK_LIMITED|NODE_WITNESS once we are near the tip
(GetDesirableServiceFlags :1759-1768) — and every peer must announce at least
MIN_PEER_PROTO_VERSION. Inbound, manual and feeler connections are exempt from
the services gate (CNode::ExpectServicesFromConn)."
  (let ((full (logior bl.ser:+node-network+
                      bl.ser:+node-witness+))
        (limited (logior bl.ser:+node-network-limited+
                         bl.ser:+node-witness+)))
    (is (= 31800 bl.net::+min-peer-proto-version+))
    (is-true (bl.net::has-all-desirable-service-flags-p full nil))
    (is-false (bl.net::has-all-desirable-service-flags-p 0 nil))
    (is-false (bl.net::has-all-desirable-service-flags-p
               bl.ser:+node-network+ nil))   ; no witness
    ;; A limited peer is desirable only near the tip.
    (is-false (bl.net::has-all-desirable-service-flags-p limited nil))
    (is-true (bl.net::has-all-desirable-service-flags-p limited t))
    (flet ((expects (&rest args)
             (bl.net::peer-outbound-or-block-relay-p
              (apply #'bl.net:make-peer args))))
      (is-true (expects :conn-type :outbound-full-relay))
      (is-true (expects :conn-type :block-relay))
      (is-false (expects :conn-type :outbound-full-relay :manual t))
      (is-false (expects :conn-type :feeler))
      (is-false (expects :conn-type :inbound)))))
