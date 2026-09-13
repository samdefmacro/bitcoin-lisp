(in-package #:bitcoin-lisp.tests)

(def-suite :conn-type-tests
  :description "Connection types: block-relay-only and feeler tx-relay gating"
  :in :bitcoin-lisp-tests)

(in-suite :conn-type-tests)

(test peer-ids-start-at-zero
  "Core's CConnman::GetNewNodeId is `nLastNodeId.fetch_add(1)' over a counter
initialised to 0 (net.cpp:3390-3393, net.h:1609): it hands out the value BEFORE
the increment, so a node's FIRST peer is id 0. Ours incremented first and every
id was one too high -- p2p_addrfetch.py:40 and p2p_mutated_blocks.py:77 both
assert `info[0]['id'] == 0' on a node's first peer."
  (let ((bl.net::*peer-id-counter* 0))
    (is (= 0 (bl.net:peer-id (bl.net:make-peer))) "the first peer is id 0")
    (is (= 1 (bl.net:peer-id (bl.net:make-peer))) "the second is id 1")
    (is (= 2 (bl.net:peer-id (bl.net:make-peer))))))

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
             (bl.net:peer-outbound-or-block-relay-p
              (apply #'bl.net:make-peer args))))
      (is-true (expects :conn-type :outbound-full-relay))
      (is-true (expects :conn-type :block-relay))
      (is-false (expects :conn-type :manual))
      (is-false (expects :conn-type :feeler))
      (is-false (expects :conn-type :inbound)))))
