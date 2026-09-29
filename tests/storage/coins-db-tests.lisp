(in-package #:bitcoin-lisp.tests)

;;;; The coins database in Bitcoin Core's chainstate format
;;;; (src/storage/coins-view.lisp; Core txdb.cpp, dbwrapper.cpp, coins.h).
;;;;
;;;; The contract is byte-exactness with Core, so the vectors are Core's own
;;;; bytes: records read out of a regtest chainstate/ that Bitcoin Core v28.2
;;;; wrote (/releases/v28.2/bin/bitcoind -regtest, generatetodescriptor 2 to
;;;; each of P2PKH, P2SH, P2PK compressed, P2PK uncompressed, P2WPKH and
;;;; OP_TRUE, 100 more to OP_TRUE, then a transaction with 300 OP_TRUE outputs
;;;; mined at height 113; clean stop; 2026-09-29), and the Coin vectors of
;;;; Core's src/test/coins_tests.cpp:522-567. The second half covers the
;;;; in-place upgrade from this tree's own pre-2026-09-29 layout.

(def-suite :coins-db-tests
  :description "Core's chainstate LevelDB format, and the upgrade to it"
  :in :bitcoin-lisp-tests)

(in-suite :coins-db-tests)

(defun %cdb-octets (hex)
  (coerce (bl.crypto:hex-to-bytes hex) '(simple-array (unsigned-byte 8) (*))))

(defparameter *core-coins-db-obfuscation-key* "f05601d64c9c2c8b"
  "The obfuscation key Core v28.2 drew for that chainstate: its
`\\000obfuscate_key' record is 08f05601d64c9c2c8b.")

(defparameter *core-coin-records*
  ;; key, obfuscated value, height, coinbase, amount, scriptPubKey
  '(("43019627d2af1a793db832bfbb21322b0f30110da93b95a6096ef073612394889f00"
     "83640687" 57 t 5000000000 "51")
    ("43049691ea348982aedb9c145b41e646ef839b3811f7e3fe3a0ad7b01915938fa100"
     "ff6405aff2fa52722cedad83ecfeb945775d06d4d760f7a63e7ed88fbe1d779d084199" 7 t 5000000000
     "410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac")
    ("434cde01912b78c7b2d4ba1bc87f5a1dbac887f59ecb6e6e89a54798a45682dfdf00"
     "f56401d64d9e2f8ff55006de45962787fd580ec65d8e3f" 2 t 5000000000
     "76a914000102030405060708090a0b0c0d0e0f1011121388ac")
    ("438da7e05c84adb1fe145d8d06e82b26bfe90ff013672a1deff51d0c12359953a600"
     "e5641dd6583697472db8fed65dbe1fcfa530765ed53697472d" 10 t 5000000000
     "0014aabbccddeeff00112233445566778899aabbccdd")
    ("43a8660ea97107b30526e1fcee5cd2f0fada9dd2728e6a33dd36cb3eb6da66a04400"
     "fb6403aff2fa52722cedad83ecfeb945775d06d4d760f7a63e7ed88fbe1d779d084199" 5 t 5000000000
     "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac")
    ("43b65b44c6a2889c8b9671b67797c4632980ce840655dd3b8acd87f2459aa5b6be00"
     "f7640029a241e0305acf89a12ac968b8d2470129a241e0" 3 t 5000000000
     "a914ffeeddccbbaa99887766554433221100ffeeddcc87")
    ;; The 300-output transaction: vouts 127, 128, 255, 256 and 299, whose
    ;; VARINTs are 7f, 8000, 807f, 8100 and 812b.
    ("436e99e8fdf6e62fbf990c13a432b29a68bd514c481e1b9bbbc29f9662d832a8307f"
     "703409d11d" 113 nil 10000000 "51")
    ("436e99e8fdf6e62fbf990c13a432b29a68bd514c481e1b9bbbc29f9662d832a8308000"
     "703409d11d" 113 nil 10000000 "51")
    ("436e99e8fdf6e62fbf990c13a432b29a68bd514c481e1b9bbbc29f9662d832a830807f"
     "703409d11d" 113 nil 10000000 "51")
    ("436e99e8fdf6e62fbf990c13a432b29a68bd514c481e1b9bbbc29f9662d832a8308100"
     "703409d11d" 113 nil 10000000 "51")
    ("436e99e8fdf6e62fbf990c13a432b29a68bd514c481e1b9bbbc29f9662d832a830812b"
     "703409d11d" 113 nil 10000000 "51"))
  "Coin records of the Core-written chainstate, one per script form plus
five of the 300-output transaction's.")

(defparameter *core-best-block-record* "c822f8f389fac1b57bcde8f70de5a3abf5f62b4bcad9adf3ab5986a1b8caeeae"
  "Core's obfuscated 'B' value there; the chain tip was block 113,
25c256f477870f5b788145869d2aa005208f794121e99b8b3eed66c525f97438.")

(defun %core-vouts ()
  (mapcar (lambda (r) (nth-value 1 (bl.store:decode-coin-key (%cdb-octets (first r)))))
          *core-coin-records*))

(test core-coin-records-are-read-and-written-byte-for-byte
  "Every Core record decodes -- the CoinEntry key to its txid and VARINT vout,
the value, once XORed with the database's key, to the Coin Core wrote -- and
encoding the decoded coin and XORing it again gives Core's bytes back. That is
both directions of the format at once: we read what Core writes, and what we
write is what Core would have."
  (let ((key (%cdb-octets *core-coins-db-obfuscation-key*)))
    (is (equal '(0 0 0 0 0 0 127 128 255 256 299) (%core-vouts)))
    (dolist (r *core-coin-records*)
      (destructuring-bind (key-hex value-hex height coinbase amount script-hex) r
        (let* ((k (%cdb-octets key-hex))
               (stored (%cdb-octets value-hex))
               (entry (bl.store:decode-coin-value
                       (bl.store:obfuscate! (copy-seq stored) key))))
          (multiple-value-bind (txid vout) (bl.store:decode-coin-key k)
            (is (equalp k (bl.store:encode-coin-key (bl.store:make-utxo-key txid vout)))
                "the key of vout ~D does not re-encode to Core's" vout))
          (is (= height (bl.store:utxo-entry-height entry)))
          (is (eq coinbase (bl.store:utxo-entry-coinbase entry)))
          (is (= amount (bl.store:utxo-entry-value entry)))
          (is (equalp (%cdb-octets script-hex) (bl.store:utxo-entry-script-pubkey entry)))
          (is (equalp stored (bl.store:obfuscate! (bl.store:encode-coin-value entry) key))
              "re-encoding the coin at height ~D changed Core's bytes" height))))))

(test core-coin-serialization-vectors
  "Core's ccoins_serialization (src/test/coins_tests.cpp:522-567): two real
coins, the smallest possible record, and two records whose script runs past
the end of the data, which must fail rather than read a short script."
  (flet ((coin (hex) (bl.store:decode-coin-value (%cdb-octets hex))))
    (let ((cc1 (coin "97f23c835800816115944e077fe7c803cfa57f29b36bf87c1d35"))
          (cc2 (coin "8ddf77bbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa4"))
          (cc3 (coin "000006")))
      (is (not (bl.store:utxo-entry-coinbase cc1)))
      (is (= 203998 (bl.store:utxo-entry-height cc1)))
      (is (= 60000000000 (bl.store:utxo-entry-value cc1)))
      (is (equalp (%cdb-octets "76a914816115944e077fe7c803cfa57f29b36bf87c1d3588ac")
                  (bl.store:utxo-entry-script-pubkey cc1)))
      (is (bl.store:utxo-entry-coinbase cc2))
      (is (= 120891 (bl.store:utxo-entry-height cc2)))
      (is (= 110397 (bl.store:utxo-entry-value cc2)))
      (is (equalp (%cdb-octets "76a9148c988f1a4a4de2161e0f50aac7f17e7f9555caa488ac")
                  (bl.store:utxo-entry-script-pubkey cc2)))
      (is (not (bl.store:utxo-entry-coinbase cc3)))
      (is (= 0 (bl.store:utxo-entry-height cc3)))
      (is (= 0 (bl.store:utxo-entry-value cc3)))
      (is (= 0 (length (bl.store:utxo-entry-script-pubkey cc3))))
      (dolist (pair (list (cons cc1 "97f23c835800816115944e077fe7c803cfa57f29b36bf87c1d35")
                          (cons cc2 "8ddf77bbd123008c988f1a4a4de2161e0f50aac7f17e7f9555caa4")
                          (cons cc3 "000006")))
        (is (equalp (%cdb-octets (cdr pair)) (bl.store:encode-coin-value (car pair))))))
    (signals error (coin "000007"))
    (signals error (coin "00008a95c0bb00"))))

(defun %cdb-bytes< (a b)
  "LevelDB's default comparator: unsigned bytes, then length."
  (let ((m (mismatch a b)))
    (cond ((null m) nil)
          ((>= m (length a)) t)
          ((>= m (length b)) nil)
          (t (< (aref a m) (aref b m))))))

(test coin-key-order-is-not-numeric-and-the-walk-regroups
  "Core's VARINT sorts numerically only among encodings of one length: 16512
is 80 80 00 and sorts before 256, which is 81 00, so LevelDB's order of one
txid's CoinEntry keys -- Core's cursor order -- is not the numeric vout order.
kernel/coinstats.cpp:112-146 regroups each txid through a std::map before
hashing, and so must UTXO-SET-ITERATE over a LevelDB-backed view: the hash
of a set and dumptxoutset's order both depend on it."
  (let* ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (vouts '(0 1 127 128 255 256 16511 16512 70000))
         (keys (mapcar (lambda (v) (bl.store:encode-coin-key (bl.store:make-utxo-key txid v)))
                       vouts)))
    (is (equal '(34 34 34 35 35 35 35 36 36) (mapcar #'length keys)))
    (is (equal '(0 1 127 128 255 16512 256 70000 16511)
               (mapcar (lambda (k) (nth-value 1 (bl.store:decode-coin-key k)))
                       (sort (copy-list keys) #'%cdb-bytes<)))
        "the key order is Core's VARINT byte order")
    (with-temp-directory (dir "bl-coins-order")
      (bl.store:with-coins-view-db (view (namestring (merge-pathnames "cs/" dir)))
        (let ((cache (bl.store:make-coins-view-cache view))
              (walked '()))
          (dolist (v (reverse vouts))
            (bl.store:add-utxo cache txid v 1000 (make-array 1 :element-type '(unsigned-byte 8)
                                                               :initial-element #x51)
                               1))
          (bl.store:coins-view-cache-flush cache)
          (bl.store:utxo-set-iterate cache (lambda (tx v e) (declare (ignore tx e))
                                             (push v walked)))
          (is (equal vouts (nreverse walked)) "the walk delivers numeric order"))))))

(defun %cdb-coin (value height &key coinbase (script #(#x51)))
  (bl.store:make-utxo-entry :value value :height height :coinbase coinbase
                            :script-pubkey (coerce script '(simple-array (unsigned-byte 8) (*)))))

(defun %cdb-raw-records (path)
  "Every record of the LevelDB at PATH as (key . value), in key order."
  (let ((out '()))
    (bl.store:with-leveldb (db path)
      (bl.store:with-leveldb-iterator (it db)
        (bl.store:leveldb-iter-seek-to-first it)
        (loop while (bl.store:leveldb-iter-valid-p it)
              do (push (cons (bl.store:leveldb-iter-key it) (bl.store:leveldb-iter-value it)) out)
                 (bl.store:leveldb-iter-next it))))
    (nreverse out)))

(defun %cdb-obfuscation-key (records)
  (subseq (cdr (find (%cdb-octets "0e006f62667573636174655f6b6579") records
                     :key #'car :test #'equalp))
          1))

(test values-are-obfuscated-with-the-databases-random-key
  "CDBWrapper XORs every VALUE it writes with the database's key and stores
the key record itself plain (dbwrapper.cpp:173-180, :253-261); keys are never
obfuscated. So on disk a coin is its Coin serialization XOR the key, 'B' is
the block hash XOR the key and 'H' the two-hash vector XOR the key -- and a
second database gets a different key."
  (with-temp-directory (dir "bl-coins-obf")
    (let* ((path (namestring (merge-pathnames "chainstate/" dir)))
           (other (namestring (merge-pathnames "other/" dir)))
           (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
           (entry (%cdb-coin 12345 77 :coinbase t))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB))
           (old (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCD)))
      (bl.store:with-coins-view-db (view path)
        (bl.store:with-coins-view-batch (batch view)
          (bl.store:coins-view-batch-put view batch (bl.store:make-utxo-key txid 300) entry)
          (bl.store:coins-view-batch-set-best-block view batch tip)
          (bl.store:coins-view-batch-set-head-blocks view batch tip old))
        (is (equalp tip (bl.store:coins-view-db-best-block view)))
        (is (equalp (list tip old) (bl.store:coins-view-db-head-blocks view))))
      (bl.store:with-coins-view-db (view other) view)
      (let* ((records (%cdb-raw-records path))
             (key (%cdb-obfuscation-key records)))
        (is-true (bl.store:obfuscation-key-active-p key))
        (is (not (equalp key (%cdb-obfuscation-key (%cdb-raw-records other))))
            "two new databases drew the same key")
        (flet ((stored (k) (cdr (find k records :key #'car :test #'equalp)))
               (xor (v) (bl.store:obfuscate! (copy-seq v) key)))
          (is (equalp (xor (bl.store:encode-coin-value entry))
                      (stored (bl.store:encode-coin-key (bl.store:make-utxo-key txid 300)))))
          (is (equalp (xor tip) (stored (%cdb-octets "42"))))
          (is (equalp (xor (concatenate '(simple-array (unsigned-byte 8) (*)) #(2) tip old))
                      (stored (%cdb-octets "48")))))))))

(test a-chainstate-core-wrote-reads-through-the-view
  "The Core records written into a LevelDB exactly as Core left them -- the key
record, 'B' and the coins -- read back through the coins view: GetCoin, the
best block, and the cursor walk in Core's order (txid, then numeric vout)."
  (with-temp-directory (dir "bl-core-cs")
    (let ((path (namestring (merge-pathnames "chainstate/" dir))))
      (bl.store:with-leveldb (db path)
        (bl.store:leveldb-put db (%cdb-octets "0e006f62667573636174655f6b6579")
                              (%cdb-octets (concatenate 'string "08" *core-coins-db-obfuscation-key*)))
        (bl.store:leveldb-put db (%cdb-octets "42") (%cdb-octets *core-best-block-record*))
        (dolist (r *core-coin-records*)
          (bl.store:leveldb-put db (%cdb-octets (first r)) (%cdb-octets (second r)))))
      (bl.store:with-coins-view-db (view path)
        (is (equalp (bl.crypto:reverse-bytes
                     (%cdb-octets "25c256f477870f5b788145869d2aa005208f794121e99b8b3eed66c525f97438"))
                    (bl.store:coins-view-db-best-block view)))
        (is-false (bl.store:coins-view-db-legacy-layout-p view)
                  "Core's layout is not mistaken for the old one")
        (dolist (r *core-coin-records*)
          (multiple-value-bind (txid vout) (bl.store:decode-coin-key (%cdb-octets (first r)))
            (let ((e (bl.store:coins-view-db-get view (bl.store:make-utxo-key txid vout))))
              (is (and e (= (fifth r) (bl.store:utxo-entry-value e))
                       (= (third r) (bl.store:utxo-entry-height e)))))))
        (let ((walked '()))
          (bl.store:utxo-set-iterate (bl.store:make-coins-view-cache view)
                                     (lambda (txid vout entry)
                                       (declare (ignore entry))
                                       (push (bl.store:encode-coin-key
                                              (bl.store:make-utxo-key txid vout))
                                             walked)))
          (is (equalp (sort (mapcar (lambda (r) (%cdb-octets (first r))) *core-coin-records*)
                            #'%cdb-bytes<)
                      (nreverse walked))))))))

;;;; The upgrade from this tree's old layout

(defun %write-old-layout-coins-db (path coins &key best-block head-blocks)
  "A coins LevelDB in this tree's pre-2026-09-29 layout, as the old writer
left it: the zero obfuscation key, 'C' + txid + LE u32 vout -> i64 value,
u32 height, u8 coinbase, u32 script length, script -- all plain -- and plain
'B'/'H'. COINS is a list of (txid vout utxo-entry)."
  (bl.store:with-leveldb (db path)
    (bl.store:leveldb-put db (%cdb-octets "0e006f62667573636174655f6b6579")
                          (%cdb-octets "080000000000000000"))
    (when best-block (bl.store:leveldb-put db (%cdb-octets "42") best-block))
    (when head-blocks
      (bl.store:leveldb-put db (%cdb-octets "48")
                            (concatenate '(simple-array (unsigned-byte 8) (*))
                                         #(2) (first head-blocks) (second head-blocks))))
    (dolist (c coins)
      (destructuring-bind (txid vout e) c
        (let ((k (make-array 37 :element-type '(unsigned-byte 8)))
              (script (bl.store:utxo-entry-script-pubkey e)))
          (setf (aref k 0) #x43)
          (replace k txid :start1 1)
          (dotimes (i 4) (setf (aref k (+ 33 i)) (ldb (byte 8 (* 8 i)) vout)))
          (bl.store:leveldb-put
           db k (concatenate '(simple-array (unsigned-byte 8) (*))
                             (loop for i below 8 collect (ldb (byte 8 (* 8 i)) (bl.store:utxo-entry-value e)))
                             (loop for i below 4 collect (ldb (byte 8 (* 8 i)) (bl.store:utxo-entry-height e)))
                             (list (if (bl.store:utxo-entry-coinbase e) 1 0))
                             (loop for i below 4 collect (ldb (byte 8 (* 8 i)) (length script)))
                             script)))))))

(defun %old-layout-coins (n)
  "N spendable coins over N/3 txids with vouts up to 300, plus one OP_RETURN
coin, which the old writer never stored but an upgrade must drop if it finds."
  (append
   (loop for i below n
         collect (let ((txid (make-array 32 :element-type '(unsigned-byte 8))))
                   (setf (aref txid 0) (mod (* 37 (floor i 3)) 256)
                         (aref txid 1) (floor i 3))
                   (list txid (* 150 (mod i 3))
                         (%cdb-coin (+ 546 i) (1+ i) :coinbase (evenp i)
                                    :script (if (zerop (mod i 5))
                                                (concatenate 'vector #(#x76 #xa9 20) (make-array 20 :initial-element i) #(#x88 #xac))
                                                #(#x51))))))
   (list (list (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE)
               0 (%cdb-coin 0 5 :script #(#x6a 1 2))))))

(defun %expected-set-hash (coins)
  (let ((set (bl.store:make-utxo-set)))
    (loop for (txid vout e) in coins
          unless (= #x6a (aref (bl.store:utxo-entry-script-pubkey e) 0))
            do (bl.store:add-utxo set txid vout (bl.store:utxo-entry-value e)
                                  (bl.store:utxo-entry-script-pubkey e)
                                  (bl.store:utxo-entry-height e)
                                  :coinbase (bl.store:utxo-entry-coinbase e)))
    (bl.store:compute-utxo-set-hash set)))

(defun %old-layout-keys (path)
  (count-if (lambda (r) (and (= 37 (length (car r))) (= #x43 (aref (car r) 0))))
            (%cdb-raw-records path)))

(test an-old-layout-coins-database-is-upgraded-to-cores
  "A coins database this tree wrote before 2026-09-29 converts in place, as
Core 0.15 converted its own (CCoinsViewDB::Upgrade): the view does not see
the old records at all until it has run (the control), and afterwards every
coin reads back, the set hashes to what the same coins hash to in memory, the
OP_RETURN coin is gone as Core's upgrade dropped unspendable ones, 'B' and 'H'
survive under the random key the upgrade installed, and no 37-byte key is
left. Running it again is a no-op, and a database already in Core's layout
is never taken for the old one."
  (with-temp-directory (dir "bl-coins-upgrade")
    (let* ((path (namestring (merge-pathnames "chainstate/" dir)))
           (coins (%old-layout-coins 60))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
           (old (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))
           (probe (first coins)))
      (%write-old-layout-coins-db path coins :best-block tip :head-blocks (list tip old))
      (bl.store:with-coins-view-db (view path)
        (is-true (bl.store:coins-view-db-legacy-layout-p view))
        (is (null (bl.store:coins-view-db-get
                   view (bl.store:make-utxo-key (first probe) (second probe))))
            "control: the old records are invisible through Core's layout")
        (is-true (bl.store:upgrade-coins-view-db view :batch-bytes 400))
        (is-false (bl.store:coins-view-db-legacy-layout-p view))
        (is (equalp tip (bl.store:coins-view-db-best-block view)))
        (is (equalp (list tip old) (bl.store:coins-view-db-head-blocks view)))
        (loop for (txid vout e) in (butlast coins)
              do (let ((got (bl.store:coins-view-db-get view (bl.store:make-utxo-key txid vout))))
                   (is (and got (= (bl.store:utxo-entry-value e) (bl.store:utxo-entry-value got))
                            (equalp (bl.store:utxo-entry-script-pubkey e)
                                    (bl.store:utxo-entry-script-pubkey got))
                            (eq (bl.store:utxo-entry-coinbase e) (bl.store:utxo-entry-coinbase got))))))
        (is (null (bl.store:coins-view-db-get
                   view (bl.store:make-utxo-key (first (car (last coins))) 0)))
            "the OP_RETURN coin was dropped")
        (is (equalp (%expected-set-hash coins)
                    (bl.store:compute-utxo-set-hash (bl.store:make-coins-view-cache view))))
        (is-true (bl.store:upgrade-coins-view-db view) "a second run is a no-op"))
      (is (= 0 (%old-layout-keys path)))
      (is-true (bl.store:obfuscation-key-active-p
                (%cdb-obfuscation-key (%cdb-raw-records path))))
      (with-temp-directory (dir2 "bl-coins-new")
        (let ((fresh (namestring (merge-pathnames "chainstate/" dir2))))
          (bl.store:with-coins-view-db (view fresh)
            (bl.store:coins-view-db-put view (bl.store:make-utxo-key (first probe) 7)
                                        (third probe))
            (is-false (bl.store:coins-view-db-legacy-layout-p view)
                      "a database in Core's layout is not the old one")))))))

(test an-interrupted-upgrade-continues-where-it-committed
  "The upgrade commits in batches, each recording how far it got, and stops
between batches when the node is asked to (Core 0.15's ShutdownRequested
check). Interrupted after its first batch, the database holds both layouts and
still says it is unfinished; reopened -- a restart -- the upgrade continues
under the key the first batch installed and ends with the same set an
uninterrupted run gives."
  (with-temp-directory (dir "bl-coins-upgrade-resume")
    (let* ((path (namestring (merge-pathnames "chainstate/" dir)))
           (coins (%old-layout-coins 90))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x33))
           (key nil))
      (%write-old-layout-coins-db path coins :best-block tip)
      (bl.store:with-coins-view-db (view path)
        (let ((bitcoin-lisp:*interrupt-check* (constantly t)))
          (is-false (bl.store:upgrade-coins-view-db view :batch-bytes 400)
                    "the stop request ends the run after one batch")))
      (let ((left (%old-layout-keys path)))
        (is (< 0 left 90) "one batch converted, the rest did not (~D left)" left))
      (setf key (%cdb-obfuscation-key (%cdb-raw-records path)))
      (bl.store:with-coins-view-db (view path)
        (is-true (bl.store:coins-view-db-legacy-layout-p view) "still unfinished")
        (is (equalp tip (bl.store:coins-view-db-best-block view))
            "'B' reads under the key the first batch installed")
        (is-true (bl.store:upgrade-coins-view-db view :batch-bytes 400))
        (is (equalp (%expected-set-hash coins)
                    (bl.store:compute-utxo-set-hash (bl.store:make-coins-view-cache view)))))
      (is (= 0 (%old-layout-keys path)))
      (is (equalp key (%cdb-obfuscation-key (%cdb-raw-records path)))
          "the resumed run kept the key"))))
