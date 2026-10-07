(in-package #:bitcoin-lisp.tests)

;;;; BIP37 bloom filters and merkle blocks against Bitcoin Core's own unit
;;;; vectors (test/bloom_tests.cpp; the hex is in bloom-vectors.lisp). The
;;;; serialized filter and merkleblock are public byte contracts.

(def-suite :bloom-tests
  :description "BIP37 CBloomFilter / CMerkleBlock (Core common/bloom.cpp, merkleblock.cpp)"
  :in :bitcoin-lisp-tests)

(in-suite :bloom-tests)

(defun %bloom-hex (s) (bl.crypto:hex-to-bytes s))

(defun %uint256 (display-hex)
  "Core's uint256{\"...\"}: display hex, stored byte-reversed."
  (reverse (%bloom-hex display-hex)))

(defun %vector-tx (hex)
  (bl.ser:br-read-transaction (bl.ser:make-byte-reader-from (%bloom-hex hex))))

(defun %vector-block (hex)
  (bl.ser:br-read-bitcoin-block (bl.ser:make-byte-reader-from (%bloom-hex hex))))

(defun %matched-display (matched)
  "vMatchedTxn as (index . display-hex txid)."
  (mapcar (lambda (m) (cons (car m) (bl.crypto:bytes-to-hex (reverse (cdr m))))) matched))

(test bloom-create-insert-serialize
  "bloom_tests.cpp:36-59 and :61-82: CBloomFilter(3, 0.01, tweak, UPDATE_ALL),
three inserts, and the serialized filter byte for byte."
  (let ((f (bl.net:make-bloom-filter 3 0.01 0 bl.net:+bloom-update-all+)))
    (is-false (bl.net:bloom-contains-p f (%bloom-hex "99108ad8ed9bb6274d3980bab5a85c048f0950c8")))
    (bl.net:bloom-insert f (%bloom-hex "99108ad8ed9bb6274d3980bab5a85c048f0950c8"))
    (is-true (bl.net:bloom-contains-p f (%bloom-hex "99108ad8ed9bb6274d3980bab5a85c048f0950c8")))
    (is-false (bl.net:bloom-contains-p f (%bloom-hex "19108ad8ed9bb6274d3980bab5a85c048f0950c8")))
    (bl.net:bloom-insert f (%bloom-hex "b5a2c786d9ef4658287ced5914b37a1b4aa32eee"))
    (bl.net:bloom-insert f (%bloom-hex "b9300670b4c5366e95b2699e8b18bc75e5f729c5"))
    (is (equalp (%bloom-hex "03614e9b050000000000000001") (bl.net:serialize-bloom-filter f))))
  (let ((f (bl.net:make-bloom-filter 3 0.01 2147483649 bl.net:+bloom-update-all+)))
    (dolist (h '("99108ad8ed9bb6274d3980bab5a85c048f0950c8" "b5a2c786d9ef4658287ced5914b37a1b4aa32eee"
                 "b9300670b4c5366e95b2699e8b18bc75e5f729c5"))
      (bl.net:bloom-insert f (%bloom-hex h)))
    (is (equalp (%bloom-hex "03ce4299050000000100008001") (bl.net:serialize-bloom-filter f)))
    ;; And it reads back as the same filter.
    (is (equalp (bl.net:serialize-bloom-filter f)
                (bl.net:serialize-bloom-filter
                 (bl.net:parse-bloom-filter (bl.net:serialize-bloom-filter f)))))))

(test bloom-match
  "bloom_tests.cpp:103-172, IsRelevantAndUpdate: the txid in either spelling,
an input signature and pubkey, an output address (which then matches the
spending transaction via the inserted outpoint), an outpoint, and five
near-misses that must not match."
  (let ((tx (%vector-tx +bloom-match-tx-hex+))
        (spend (%vector-tx +bloom-match-spending-tx-hex+)))
    (flet ((fresh () (bl.net:make-bloom-filter 10 0.000001 0 bl.net:+bloom-update-all+))
           (outpoint (display n) (bl.net:outpoint-bytes (%uint256 display) n)))
      (dolist (key (list (%uint256 "b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b")
                         (%bloom-hex "6bff7fcd4f8565ef406dd5d63d4ff94f318fe82027fd4dc451b04474019f74b4")
                         (%bloom-hex "30450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a01")
                         (%bloom-hex "046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339")
                         (%bloom-hex "a266436d2965547608b9e15d9032a7b9d64fa431")
                         (outpoint "90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b" 0)))
        (let ((f (fresh)))
          (bl.net:bloom-insert f key)
          (is-true (bl.net:bloom-relevant-and-update-p f tx))))
      (let ((f (fresh)))
        (bl.net:bloom-insert f (%bloom-hex "04943fdd508053c75000106d3bc6e2754dbcff19"))
        (is-true (bl.net:bloom-relevant-and-update-p f tx) "output address")
        (is-true (bl.net:bloom-relevant-and-update-p f spend) "UPDATE_ALL added the output"))
      (dolist (key (list (%uint256 "00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436")
                         (%bloom-hex "0000006d2965547608b9e15d9032a7b9d64fa431")
                         (outpoint "90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b" 1)
                         (outpoint "000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b" 0)))
        (let ((f (fresh)))
          (bl.net:bloom-insert f key)
          (is-false (bl.net:bloom-relevant-and-update-p f tx)))))))

(defun %merkle-block-checks (block filter expected)
  "CMerkleBlock(BLOCK, FILTER): vMatchedTxn is EXPECTED ((index . display-txid)
...), and ExtractMatches recovers the header's merkle root and those txids."
  (multiple-value-bind (payload matched) (bl.net:make-merkle-block block filter)
    (is (equal expected (%matched-display matched)))
    (multiple-value-bind (header ntx hashes bits) (bl.net:parse-merkle-block payload)
      (declare (ignore header))
      (multiple-value-bind (root txids) (bl.net:extract-partial-merkle-tree ntx bits hashes)
        (is (equalp (bl.ser:block-header-merkle-root (bl.ser:bitcoin-block-header block)) root))
        (is (equalp (mapcar #'cdr matched) txids))))
    payload))

(test merkle-block-2-update-all-and-none
  "bloom_tests.cpp:215-324: UPDATE_ALL follows a matched pay-to-pubkey output
into the transaction that spends it (4 matches); UPDATE_NONE does not (3)."
  (dolist (case `((,bl.net:+bloom-update-all+ 4) (,bl.net:+bloom-update-none+ 3)))
    (destructuring-bind (flags n) case
      (let ((block (%vector-block +merkle-block-2-hex+))
            (f (bl.net:make-bloom-filter 10 0.000001 0 flags)))
        (bl.net:bloom-insert f (%uint256 "e980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df5b47aecb93b70"))
        (%merkle-block-checks block f '((0 . "e980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df5b47aecb93b70")))
        (bl.net:bloom-insert f (%bloom-hex "044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45af"))
        (%merkle-block-checks
         block f
         (if (= n 4)
             '((0 . "e980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df5b47aecb93b70")
               (1 . "28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f")
               (2 . "6b0f8a73a56c04b519f1883e8aafda643ba61a30bd1439969df21bea5f4e27e2")
               (3 . "3c1d7e82342158e4109df2e0b6348b6e84e403d8b4046d7007663ace63cddb23"))
             '((0 . "e980fe9f792d014e73b95203dc1335c5f9ce19ac537a419e6df5b47aecb93b70")
               (1 . "28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f")
               (3 . "3c1d7e82342158e4109df2e0b6348b6e84e403d8b4046d7007663ace63cddb23"))))))))

(test merkle-block-3-serializes-byte-for-byte
  "bloom_tests.cpp:326-360: a one-transaction block, matched, serializes to
Core's exact merkleblock bytes."
  (let ((block (%vector-block +merkle-block-3-hex+))
        (f (bl.net:make-bloom-filter 10 0.000001 0 bl.net:+bloom-update-all+)))
    (bl.net:bloom-insert f (%uint256 "63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5"))
    (is (equalp (%bloom-hex "0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101")
                (%merkle-block-checks
                 block f '((0 . "63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5")))))))

(test merkle-block-4-and-the-update-flags
  "bloom_tests.cpp:362-463: two matches in a seven-transaction block, and the
flags: P2PUBKEY_ONLY inserts the matched pay-to-pubkey generation outpoint
but not the pay-to-pubkey-hash one; NONE inserts neither."
  (let ((block (%vector-block +merkle-block-4-hex+))
        (f (bl.net:make-bloom-filter 10 0.000001 0 bl.net:+bloom-update-all+)))
    (bl.net:bloom-insert f (%uint256 "0a2a92f0bda4727d0a13eaddf4dd9ac6b5c61a1429e6b2b818f19b15df0ac154"))
    (%merkle-block-checks block f '((6 . "0a2a92f0bda4727d0a13eaddf4dd9ac6b5c61a1429e6b2b818f19b15df0ac154")))
    (bl.net:bloom-insert f (%uint256 "02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc041"))
    (%merkle-block-checks block f '((3 . "02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc041")
                                    (6 . "0a2a92f0bda4727d0a13eaddf4dd9ac6b5c61a1429e6b2b818f19b15df0ac154"))))
  (dolist (case `((,bl.net:+bloom-update-p2pubkey-only+ t) (,bl.net:+bloom-update-none+ nil)))
    (destructuring-bind (flags generation-inserted) case
      (let ((block (%vector-block +merkle-block-4-hex+))
            (f (bl.net:make-bloom-filter 10 0.000001 0 flags)))
        (bl.net:bloom-insert f (%bloom-hex "04eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91"))
        (bl.net:bloom-insert f (%bloom-hex "b6efd80d99179f4f4ff6f4dd0a007d018c385d21"))
        (bl.net:make-merkle-block block f)
        (is (eq generation-inserted
                (bl.net:bloom-contains-p
                 f (bl.net:outpoint-bytes
                    (%uint256 "147caa76786596590baa4e98f5d9f48b86c7765e489f7a6ff3360fe5c674360b") 0))))
        (is-false (bl.net:bloom-contains-p
                   f (bl.net:outpoint-bytes
                      (%uint256 "02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc041") 0)))))))

;;;; --- The BIP37 messages (Core net_processing.cpp:4939-4966, :5051-5120) ---

(defun %filterload-payload (data &key (funcs 1) (tweak 0) (flags 0))
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-varint bb (length data))
    (bl.ser:bb-write-bytes bb data)
    (bl.ser:bb-write-u32-le bb funcs)
    (bl.ser:bb-write-u32-le bb tweak)
    (bl.ser:bb-write-u8 bb flags)
    (bl.ser:bb-finish bb)))

(defun %filteradd-payload (data)
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-varint bb (length data))
    (bl.ser:bb-write-bytes bb data)
    (bl.ser:bb-finish bb)))

(defun %bloom-peer (&key (relay t))
  "A ready full-relay peer whose version said fRelay=RELAY."
  (let ((peer (%fake-ready-peer)))
    (setf (bl.net:peer-version peer)
          (bl.bytes:with-byte-reader (in (bl.ser:make-version-message-bytes :relay relay))
            (bl.ser:read-version-message in)))
    peer))

(defun %bloom-dispatch-log (peer command payload)
  (nth-value 1 (log-text-of "net" (lambda () (%dispatch-to-fake-peer command payload peer)))))

(test bloom-messages-follow-cores-handlers
  "With -peerbloomfilters: a filter over MAX_BLOOM_FILTER_SIZE or with more
than MAX_HASH_FUNCS is Misbehaving, one at the limits is loaded; a filteradd
over MAX_SCRIPT_ELEMENT_SIZE, or with no filter loaded, is Misbehaving; and a
filterload turns relay on for an fRelay=0 peer, whose tx-relay object existed
all along because we offer it NODE_BLOOM (getpeerinfo relaytxes false until
then). p2p_filter.py:110-139 and :246-255. Ours refused all three outright."
  (let ((bl:*peer-bloom-filters* t))
    (let ((peer (%bloom-peer)))
      (is (search "Misbehaving" (%bloom-dispatch-log peer "filterload"
                                                     (%filterload-payload (make-array 36001 :initial-element #xbb)))))
      (is (eq :disconnected (bl.net:peer-state peer))))
    (let ((peer (%bloom-peer)))
      (is (search "Misbehaving" (%bloom-dispatch-log peer "filterload"
                                                     (%filterload-payload #(#xaa) :funcs 51)))))
    (let ((peer (%bloom-peer)))
      (is (not (search "Misbehaving" (%bloom-dispatch-log peer "filterload"
                                                          (%filterload-payload (make-array 36000 :initial-element #xbb) :funcs 50)))))
      (is-true (bl.net:peer-bloom-filter peer))
      (is (not (search "Misbehaving" (%bloom-dispatch-log peer "filteradd"
                                                          (%filteradd-payload (make-array 520 :initial-element #xcc))))))
      (is (search "Misbehaving" (%bloom-dispatch-log peer "filteradd"
                                                     (%filteradd-payload (make-array 521 :initial-element #xcc))))))
    (let ((peer (%bloom-peer)))
      (%dispatch-to-fake-peer "filterclear" #() peer)
      (is (null (bl.net:peer-bloom-filter peer)))
      (is (search "Misbehaving" (%bloom-dispatch-log peer "filteradd" (%filteradd-payload #(1 2 3))))
          "filteradd with no filter loaded"))
    (let ((peer (%bloom-peer :relay nil)))
      (is-true (bl.net:peer-tx-relay-state-p peer) "NODE_BLOOM offered: the tx-relay object exists")
      (is-false (bl.net:peer-tx-relay-p peer) "but fRelay=0 relays nothing yet")
      (%dispatch-to-fake-peer "filterload" (%filterload-payload #(0 0 0 0) :funcs 1) peer)
      (is-true (bl.net:peer-tx-relay-p peer) "a filterload turns relay on")))
  ;; Without -peerbloomfilters: refused and disconnected, with Core's line.
  (let ((bl:*peer-bloom-filters* nil)
        (peer (%bloom-peer)))
    (is (search "filterload received despite not offering bloom services"
                (%bloom-dispatch-log peer "filterload" (%filterload-payload #(1)))))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test mempool-message-is-refused-only-where-core-refuses-it
  "Core's MEMPOOL handler (net_processing.cpp:4939-4958): without NODE_BLOOM
and the mempool permission it disconnects -- but never a noban peer, which
Core keeps (ours dropped it too)."
  (let ((bl:*peer-bloom-filters* nil))
    (let ((peer (%bloom-peer)))
      (is (search "mempool request with bloom filters disabled"
                  (%bloom-dispatch-log peer "mempool" #())))
      (is (eq :disconnected (bl.net:peer-state peer))))
    (with-whitelist (:entries '("noban@127.0.0.1"))
      (let ((peer (%bloom-peer)))
        (setf (bl.net:peer-inbound peer) t)
        (is-true (bl.net:peer-has-permission-p peer bl.net:+perm-noban+))
        (%dispatch-to-fake-peer "mempool" #() peer)
        (is (eq :ready (bl.net:peer-state peer)) "a noban peer is kept")))))

;;;; Core's CRollingBloomFilter (common/bloom.cpp:162-246)

(defun %rolling-key (n)
  "A distinct 32-byte key for N, standing in for Core's RandomData()."
  (bl.crypto:sha256 (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
                      (dotimes (k 8 v) (setf (aref v k) (ldb (byte 8 (* 8 k)) n))))))

(test rolling-bloom-sizes-itself-as-core-does
  "The hash count and table size are Core's constructor's (bloom.cpp:162-187),
pinned for the filters Core builds: the tx-download ones (120,000 and 48,000
at one in a million, txdownloadman_impl.h:61-66, :91-96, :120-128) and
bloom_tests.cpp's two."
  (loop for (n fp funcs words) in '((120000 0.000001d0 20 161750) (48000 0.000001d0 20 64700)
                                    (100 0.01d0 7 46) (1000 0.001d0 10 674))
        do (let ((f (bl.net:make-rolling-bloom-filter n fp 0)))
             (is (= funcs (bl.net:rolling-bloom-filter-hash-funcs f)))
             (is (= words (length (bl.net:rolling-bloom-filter-data f)))))))

(test rolling-bloom-remembers-the-last-n-and-forgets-older-ones
  "Core's rolling_bloom test (bloom_tests.cpp:465-533) on our keys: a
last-100 filter at 1% remembers the last 100 of 399 insertions and about 1%
of unseen keys, forgets everything on reset, remembers each entry for the 100
insertions after it while rolling, keeps only false positives of the old
entries after 999 more, and a last-1000 filter holds all 399. Core's exact
hit counts (71, 3) come from its seeded RNG; the bounds are what they
approximate."
  (let ((rb1 (bl.net:make-rolling-bloom-filter 100 0.01d0 12345))
        (data (loop for i below 399 collect (%rolling-key i))))
    (dolist (d data) (bl.net:rolling-bloom-insert rb1 d))
    (is (every (lambda (d) (bl.net:rolling-bloom-contains-p rb1 d)) (nthcdr 299 data)))
    (let ((hits (loop for i from 10000 below 20000
                      count (bl.net:rolling-bloom-contains-p rb1 (%rolling-key i)))))
      (is (< 20 hits 200) "about 1% of 10,000 unseen keys, got ~D" hits))
    (bl.net:rolling-bloom-reset rb1)
    (is-false (bl.net:rolling-bloom-contains-p rb1 (car (last data))))
    (loop for d in data for i from 0
          do (when (>= i 100)
               (is-true (bl.net:rolling-bloom-contains-p rb1 (nth (- i 100) data))))
             (bl.net:rolling-bloom-insert rb1 d)
             (is-true (bl.net:rolling-bloom-contains-p rb1 d)))
    (dotimes (i 999)
      (let ((d (%rolling-key (+ 50000 i))))
        (bl.net:rolling-bloom-insert rb1 d)
        (is-true (bl.net:rolling-bloom-contains-p rb1 d))))
    (let ((hits (count-if (lambda (d) (bl.net:rolling-bloom-contains-p rb1 d)) data)))
      (is (< hits 20) "only false positives of the old entries remain, got ~D" hits))
    (let ((rb2 (bl.net:make-rolling-bloom-filter 1000 0.001d0)))
      (dolist (d data) (bl.net:rolling-bloom-insert rb2 d))
      (is (every (lambda (d) (bl.net:rolling-bloom-contains-p rb2 d)) data)))))

(test rolling-bloom-forgets-within-one-and-a-half-n
  "The capacity contract the tx-download filters rely on: an entry survives N
later insertions (two whole generations of N/2 follow it) and is gone once
its generation number comes round again, which is at most 1.5 N later
(bloom.cpp:168-170, :197-212) -- not a FIFO of exactly N."
  (let ((f (bl.net:make-rolling-bloom-filter 1000 0.000001d0 99))
        (old (loop for i below 100 collect (%rolling-key (+ 90000 i)))))
    (dolist (d old) (bl.net:rolling-bloom-insert f d))
    (dotimes (i 900) (bl.net:rolling-bloom-insert f (%rolling-key (+ 91000 i))))
    (is (every (lambda (d) (bl.net:rolling-bloom-contains-p f d)) old)
        "remembered across the next N insertions")
    (dotimes (i 600) (bl.net:rolling-bloom-insert f (%rolling-key (+ 92000 i))))
    (is (notany (lambda (d) (bl.net:rolling-bloom-contains-p f d)) old)
        "forgotten 1.5 N insertions later")))
