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
