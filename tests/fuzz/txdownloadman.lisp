(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/txdownloadman.cpp at the pin (d3056bc149): its two
;;;; targets over the TxDownloadManager (src/networking/txdownloadman.lisp).
;;;;
;;;; txdownloadman drives the manager through its public methods only -- peers
;;;; connecting and leaving, tip changes, blocks, mempool verdicts,
;;;; announcements, requests, deliveries, notfounds and the orphan work set --
;;;; and checks the contract of each answer: no tx validated AND offered as a
;;;; package, a package a 1-parent-1-child pair from the asking peer, an
;;;; orphan handed out only when HaveMoreWork said so, and everything empty
;;;; once every peer has gone.
;;;;
;;;; txdownloadman_impl drives the same commands against the object's inside
;;;; and checks what they must leave behind: the rejection filters empty after
;;;; a tip change, a block's transactions out of the orphanage, the confirmed
;;;; filter empty after a disconnect, nothing requested that AlreadyHaveTx
;;;; knows, a package's parent in the reconsiderable filter and its child in
;;;; the orphanage, and -- CheckInvariants -- the orphanage's and the tracker's
;;;; SanityCheck and every peer but the relay-permission one within
;;;; MAX_PEER_TX_ANNOUNCEMENTS.
;;;;
;;;; As in Core: sixteen peers (the integers 0-15, Core's NodeId), fifty coins
;;;; and the fixed transaction set the initializer builds, Core's
;;;; deterministic tracker salt (k0 = k1 = 0), a seeded random state for the
;;;; work-set draw, and a clock in Core's microseconds handed to the manager in
;;;; the seconds its delays are counted in. A TxValidationResult is the
;;;; rejection keyword of its class.

(def-suite :fuzz-txdownloadman-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/txdownloadman.cpp targets")

(in-suite :fuzz-txdownloadman-tests)

(defconstant +tdm-num-peers+ 16 "NUM_PEERS (txdownloadman.cpp:53).")

(defun tdm-coin (i)
  "COINS[I] (:85-87): the outpoint (HashWriter() << I, I) -- the double SHA256
of I's four little-endian bytes, at index I."
  (cons (bl.crypto:hash256 (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
                             (dotimes (k 4 v) (setf (aref v k) (ldb (byte 8 (* 8 k)) i)))))
        i))

(defparameter *tdm-coins*
  (coerce (loop for i below 50 collect (tdm-coin i)) 'simple-vector)
  "COINS (NUM_COINS = 50).")

(defun tdm-tx-spending (outpoints num-outputs add-witness)
  "MakeTransactionSpending (:58-70): one input per outpoint (txid . index),
the first carrying the one-element witness {1} when ADD-WITNESS, and
NUM-OUTPUTS outputs of CENT to P2WSH_OP_TRUE."
  (bl.ser:make-transaction
   :version 2
   :inputs (map 'simple-vector
                (lambda (op)
                  (bl.ser:make-tx-in
                   :previous-output (bl.ser:make-outpoint :hash (car op) :index (cdr op))
                   :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                   :sequence #xffffffff))
                outpoints)
   :outputs (coerce (loop repeat num-outputs
                          collect (bl.ser:make-tx-out :value 1000000
                                                      :script-pubkey +p2wsh-op-true+))
                    'simple-vector)
   :lock-time 0
   :witness (when add-witness
              (let ((w (make-array (length outpoints) :initial-element nil)))
                (setf (aref w 0)
                      (list (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)))
                w))))

(defun tdm-out (tx index)
  "The outpoint (txid . INDEX) of TX."
  (cons (bl.ser:transaction-hash tx) index))

(defparameter *tdm-transactions*
  (let ((txs '()) (coin 0))
    (flet ((add (tx) (push tx txs) tx))
      ;; Two transactions, same txid, different witness (:89-97).
      (add (tdm-tx-spending (list (aref *tdm-coins* coin)) 5 nil))
      (add (tdm-tx-spending (list (aref *tdm-coins* coin)) 5 t))
      (incf coin)
      ;; Two parents, one child (:98-106).
      (let* ((p1 (add (tdm-tx-spending (list (aref *tdm-coins* coin)) 1 t)))
             (p2 (add (tdm-tx-spending (list (aref *tdm-coins* (incf coin))) 1 nil))))
        (incf coin)
        (add (tdm-tx-spending (list (tdm-out p1 0) (tdm-out p2 0)) 1 t)))
      ;; One parent, two children (:107-115).
      (let ((parent (add (tdm-tx-spending (list (aref *tdm-coins* coin)) 2 t))))
        (incf coin)
        (add (tdm-tx-spending (list (tdm-out parent 0)) 1 t))
        (add (tdm-tx-spending (list (tdm-out parent 1)) 1 t)))
      ;; A chain of five segwit, then of five non-segwit (:116-133).
      (dolist (witness '(t nil))
        (let ((last (aref *tdm-coins* coin)))
          (incf coin)
          (dotimes (i 5)
            (let ((tx (add (tdm-tx-spending (list last) 1 witness))))
              (setf last (tdm-out tx 0))))))
      ;; A loose transaction for every coin (:134-138).
      (loop for c across *tdm-coins*
            do (add (tdm-tx-spending (list c) 1 t))))
    (coerce (nreverse txs) 'simple-vector))
  "TRANSACTIONS (:49-50, built by initialize, :88-138).")

(defparameter *tdm-time-skips* (subseq *txrequest-delays* 0 128)
  "TIME_SKIPS (:140-152), microseconds: the positive half of the txrequest
target's DELAYS, which Core builds the same way.")

(defparameter *tdm-tested-results*
  '(:consensus :nonstandard-inputs :not-standard :missing-input :premature-spend
    :witness-mutated :witness-stripped :conflict :mempool-policy :insufficient-fee
    :unknown)
  "TESTED_TX_RESULTS (:33-47) as rejection keywords: Core's eleven classes, in
Core's order, TX_INPUTS_NOT_STANDARD as :nonstandard-inputs,
TX_MISSING_INPUTS as :missing-input, TX_WITNESS_STRIPPED as :witness-stripped
and TX_RECONSIDERABLE as :insufficient-fee -- the four the manager tells apart
-- and the rest by name.")

(defun tdm-pick-coins (fdp)
  "PickCoins (:71-79): one coin, then up to ten more while the input says so."
  (let ((coins (list (pick-value-in-array fdp *tdm-coins*))))
    (limited-while ((consume-bool fdp) 10)
      (push (pick-value-in-array fdp *tdm-coins*) coins))
    (nreverse coins)))

(defun tdm-rand-tx (fdp)
  "The transaction one iteration works on (:185-190): a fresh one spending
picked coins, or one of TRANSACTIONS."
  (if (consume-bool fdp)
      (tdm-tx-spending (tdm-pick-coins fdp)
                       (consume-integral-in-range fdp 1 500)
                       (consume-bool fdp))
      (aref *tdm-transactions* (consume-integral-in-range fdp 0 (1- (length *tdm-transactions*))))))

(defun tdm-check-package (ptv peer)
  "CheckPackageToValidate (:155-165): two senders, the asking PEER first and a
known peer second, and a child that spends its parent."
  (fuzz-assert (eql (bl.net:ptv-parent-sender ptv) peer))
  (fuzz-assert (and (integerp (bl.net:ptv-child-sender ptv))
                    (< (bl.net:ptv-child-sender ptv) +tdm-num-peers+)))
  (fuzz-assert (orphan-fuzz-spends-p (bl.net:ptv-child ptv) (bl.net:ptv-parent ptv))
               "the package is not a child with its parent"))

(defun tdm-corpus (fdp &key impl)
  "A corpus entry for either target: the integral answers that steer one run
through a long, connected scenario, drawn from FDP. Core's targets lean on
libFuzzer's coverage feedback to find sequences that grow orphans, packages
and work sets; a seeded random buffer ends after a couple of commands. So the
entry connects a few peers and then mixes the commands, weighted toward the
ones that build state -- announcements, missing-input rejections, acceptances,
deliveries -- over the transactions that have parents in TRANSACTIONS, with
short time steps. IMPL marks the impl target, whose ConnectedPeer reads one
boolean less (the relay permission is peer 0's)."
  (let ((specs '())
        (peers (consume-integral-in-range fdp 2 4))
        (steps (consume-integral-in-range fdp 20 200)))
    (labels ((add (value min max) (push (list value min max) specs))
             (draw (n) (consume-integral-in-range fdp 0 (1- n)))
             (add-bool (v) (add (if v 1 0) 0 255))
             (add-step (peer command)
               (add-bool t)
               (add peer 0 (1- +tdm-num-peers+))
               (add-bool nil)                 ; one of TRANSACTIONS
               (add (if (< (draw 4) 3) (draw 18) (draw (length *tdm-transactions*)))
                    0 (1- (length *tdm-transactions*)))
               (add command 0 11)
               (case command
                 (0 (add-bool (zerop (draw 2)))
                  (unless impl (add-bool (zerop (draw 8))))
                  (add-bool (zerop (draw 2))))
                 ;; Missing inputs and reconsiderable most often, each as a
                 ;; first-time failure three times in four.
                 (6 (add (case (draw 4) (0 3) (1 9) (t (draw 11))) 0 10)
                  (add-bool (plusp (draw 4))))
                 (7 (add-bool (zerop (draw 2)))))
               (add (if (zerop (draw 8)) (draw 128) (draw 40)) 0 127)
               (add-bool (zerop (draw 6)))))
      (add 1700000000 946684801 4133980799)
      (dotimes (p peers) (add-step p 0))
      (dotimes (i steps)
        (add-step (draw peers)
              (let ((w (draw 100)))
                (cond ((< w 15) 7) ((< w 40) 6) ((< w 55) 5) ((< w 70) 9) ((< w 76) 8)
                      ((< w 89) 11) ((< w 92) 3) ((< w 94) 2) ((< w 96) 10) ((< w 97) 4)
                      ((< w 99) 0) (t 1)))))
      (add-bool nil))
    (fdp-integral-bytes (nreverse specs))))

(defun tdm-seconds (us)
  "Core's microsecond clock as the manager's seconds."
  (floor us 1000000))

(defmacro with-tdm-fixture ((fdp mgr time) buffer &body body)
  "Core's per-input set-up (:169-179, :294-304): SetMockTime(ConsumeTime), an
empty mempool, a deterministic manager, the clock at 244466666 us -- and the
time step every iteration ends with (:263-266)."
  `(let* ((,fdp (make-fuzzed-data-provider ,buffer))
          (bl.ser:*mock-time* (consume-integral-in-range ,fdp 946684801 4133980799))
          (,mgr (bl.net:make-txdownload-manager
                 :mempool (bl.mp:make-mempool)
                 :random-state (sb-ext:seed-random-state 0)))
          (,time 244466666))
     (with-tx-request-salt (0 0)
       ,@body)))

(defun tdm-step-time (fdp time)
  "Jump forwards or backwards by one of TIME_SKIPS (:263-266)."
  (let ((skip (pick-value-in-array fdp *tdm-time-skips*)))
    (+ time (if (consume-bool fdp) (- skip) skip))))

(defun tdm-disconnect-everybody (mgr)
  "The end of both targets (:268-273, :434-439): every peer leaves, and then
nothing of it -- and at last nothing at all -- is left."
  (dotimes (peer +tdm-num-peers+)
    (bl.net:txdownload-disconnected-peer mgr peer)
    (let ((problems (bl.net:txdownload-check-is-empty mgr peer)))
      (fuzz-assert (null (fuzz-sabotage problems)) "peer ~D: ~{~A~^; ~}" peer problems)))
  (let ((problems (bl.net:txdownload-check-is-empty mgr)))
    (fuzz-assert (null problems) "CheckIsEmpty: ~{~A~^; ~}" problems)))

(define-fuzz-target txdownloadman
    (buffer :core "txdownloadman.cpp:167-274" :iterations 250 :max-len 600
            :corpus (lambda (fdp) (tdm-corpus fdp)))
  "Through the public methods alone: a rejection that is not a first-time
failure never asks for the compact-block extra pool; ReceivedTx never says
both validate AND here is a package, and a package is a child with its
parent from the asking peer; GetTxToReconsider hands out an orphan only when
HaveMoreWork said there was one; and once every peer has disconnected the
manager holds nothing for any of them, and nothing at all."
  (with-tdm-fixture (fdp mgr time) buffer
    (limited-while ((consume-bool fdp) 500)
      (let ((peer (consume-integral-in-range fdp 0 (1- +tdm-num-peers+)))
            (tx (tdm-rand-tx fdp)))
        (call-one-of fdp
          (bl.net:txdownload-connected-peer
           mgr peer (bl.net:make-txdownload-connection-info
                     :preferred (consume-bool fdp)
                     :relay-permissions (consume-bool fdp)
                     :wtxid-relay (consume-bool fdp)))
          (progn (bl.net:txdownload-disconnected-peer mgr peer)
                 (fuzz-assert (null (bl.net:txdownload-check-is-empty mgr peer))))
          (bl.net:txdownload-active-tip-change mgr)
          (bl.net:txdownload-block-connected mgr (bl.ser:make-bitcoin-block :transactions (list tx)))
          (bl.net:txdownload-block-disconnected mgr)
          (bl.net:txdownload-mempool-accepted-tx mgr tx)
          (let ((reason (pick-value-in-array fdp *tdm-tested-results*))
                (first-time (consume-bool fdp)))
            (let ((add-extra (bl.net:txdownload-mempool-rejected-tx mgr tx reason peer first-time)))
              (fuzz-assert (or first-time (not add-extra)))))
          (if (consume-bool fdp)
              (bl.net:txdownload-add-tx-announcement mgr peer (bl.ser:transaction-hash tx) nil
                                                     (tdm-seconds time))
              (bl.net:txdownload-add-tx-announcement mgr peer (bl.ser:transaction-wtxid tx) t
                                                     (tdm-seconds time)))
          (bl.net:txdownload-get-requests-to-send mgr peer (tdm-seconds time))
          (progn
            (bl.net:txdownload-received-tx mgr peer tx)
            (multiple-value-bind (validate package) (bl.net:txdownload-received-tx mgr peer tx)
              (fuzz-assert (not (and validate (fuzz-sabotage package))))
              (when package (tdm-check-package package peer))))
          (bl.net:txdownload-received-not-found mgr peer (list (bl.ser:transaction-wtxid tx)))
          (let* ((expect-work (bl.net:txdownload-have-more-work mgr peer))
                 (orphan (bl.net:txdownload-get-tx-to-reconsider mgr peer)))
            ;; expect-work does not promise an orphan -- one can leave the
            ;; orphanage without leaving the work set -- but an orphan
            ;; promises expect-work.
            (when orphan (fuzz-assert expect-work)))))
      (setf time (tdm-step-time fdp time)))
    (tdm-disconnect-everybody mgr)))

(defun tdm-impl-filters-clear-p (mgr)
  "No TRANSACTIONS entry, by either id, in either rejection filter."
  (loop for tx across *tdm-transactions*
        always (loop for id in (list (bl.ser:transaction-wtxid tx) (bl.ser:transaction-hash tx))
                     never (or (bl.net:rolling-bloom-contains-p (bl.net:txdownload-recent-rejects mgr) id)
                               (bl.net:rolling-bloom-contains-p (bl.net:txdownload-recent-rejects-reconsiderable mgr)
                                                   id)))))

(defun tdm-check-invariants (mgr)
  "CheckInvariants (:280-290): the orphanage's and the tracker's SanityCheck,
and no peer but the relay-permission one over MAX_PEER_TX_ANNOUNCEMENTS."
  (orphan-fuzz-sanity-check (bl.net:txdownload-orphanage mgr))
  (loop for peer from 1 below +tdm-num-peers+
        do (fuzz-assert (<= (bl.net:txrequest-count (bl.net:txdownload-txrequest mgr) peer)
                            bl.net:+max-peer-tx-announcements+)))
  (let ((problems (bl.net:txrequest-sanity-check (bl.net:txdownload-txrequest mgr))))
    (fuzz-assert (null problems) "tracker SanityCheck: ~{~A~^; ~}" problems)))

(defun tdm-impl-received-tx (mgr peer tx)
  "The ReceivedTx command of txdownloadman_impl (:381-405)."
  (multiple-value-bind (validate package) (bl.net:txdownload-received-tx mgr peer tx)
    (fuzz-assert (not (and validate package)))
    (when validate
      (fuzz-assert (not (bl.net:txdownload-already-have-tx-p
                         mgr (bl.ser:transaction-wtxid tx) t t))))
    (when package
      (tdm-check-package package peer)
      (let ((reconsiderable (bl.net:txdownload-recent-rejects-reconsiderable mgr))
            (rejects (bl.net:txdownload-recent-rejects mgr)))
        ;; The parent failed reconsiderably and the child is an orphan...
        (fuzz-assert (bl.net:rolling-bloom-contains-p reconsiderable (bl.ser:transaction-wtxid tx)))
        (fuzz-assert (bl.mp:orphan-have (bl.net:txdownload-orphanage mgr)
                                        (bl.ser:transaction-wtxid (bl.net:ptv-child package))))
        ;; ...the pairing has not failed before, and neither is a reject.
        (fuzz-assert (not (bl.net:rolling-bloom-contains-p reconsiderable
                                              (bl.val:package-hash (bl.net:ptv-txns package)))))
        (fuzz-assert (not (bl.net:rolling-bloom-contains-p rejects
                                              (bl.ser:transaction-wtxid (bl.net:ptv-parent package)))))
        (fuzz-assert (not (bl.net:rolling-bloom-contains-p rejects
                                              (bl.ser:transaction-wtxid (bl.net:ptv-child package)))))))))

(define-fuzz-target txdownloadman-impl
    (buffer :core "txdownloadman.cpp:292-440" :iterations 250 :max-len 600
            :corpus (lambda (fdp) (tdm-corpus fdp :impl t)))
  "Against the object's inside: a tip change leaves no transaction in either
rejection filter; a connected block leaves none of its transactions in the
orphanage; a disconnected one leaves none in the confirmed filter; a
rejection's parents are no more than its inputs; nothing GetRequestsToSend
asks for is something AlreadyHaveTx knows; a ReceivedTx to validate is not
already had, and a package's parent is in the reconsiderable filter, its child
in the orphanage, and neither they nor their pairing rejected; an orphan from
the work set is one AlreadyHaveTx knows. At the end, CheckInvariants, and
everything empty once every peer has gone."
  (with-tdm-fixture (fdp mgr time) buffer
    (limited-while ((consume-bool fdp) 500)
      (let ((peer (consume-integral-in-range fdp 0 (1- +tdm-num-peers+)))
            (tx (tdm-rand-tx fdp)))
        (call-one-of fdp
          (bl.net:txdownload-connected-peer
           mgr peer (bl.net:make-txdownload-connection-info
                     :preferred (consume-bool fdp)
                     ;; HasRelayPermissions: peer 0 and nobody else (:276-278).
                     :relay-permissions (= peer 0)
                     :wtxid-relay (consume-bool fdp)))
          (progn (bl.net:txdownload-disconnected-peer mgr peer)
                 (fuzz-assert (null (bl.net:txdownload-check-is-empty mgr peer))))
          (progn (bl.net:txdownload-active-tip-change mgr)
                 (fuzz-assert (tdm-impl-filters-clear-p mgr)))
          (progn (bl.net:txdownload-block-connected mgr (bl.ser:make-bitcoin-block :transactions (list tx)))
                 (fuzz-assert (not (bl.mp:orphan-have (bl.net:txdownload-orphanage mgr)
                                                      (fuzz-sabotage (bl.ser:transaction-wtxid tx))))))
          (progn (bl.net:txdownload-block-disconnected mgr)
                 (let ((confirmed (bl.net:txdownload-recent-confirmed mgr)))
                   (fuzz-assert (not (bl.net:rolling-bloom-contains-p confirmed (bl.ser:transaction-wtxid tx))))
                   (fuzz-assert (not (bl.net:rolling-bloom-contains-p confirmed (bl.ser:transaction-hash tx))))))
          (bl.net:txdownload-mempool-accepted-tx mgr tx)
          (let* ((reason (pick-value-in-array fdp *tdm-tested-results*))
                 (first-time (consume-bool fdp))
                 (rejected-before (bl.net:rolling-bloom-contains-p (bl.net:txdownload-recent-rejects mgr)
                                                      (bl.ser:transaction-wtxid tx))))
            (multiple-value-bind (add-extra parents)
                (bl.net:txdownload-mempool-rejected-tx mgr tx reason peer first-time)
              (fuzz-assert (or first-time (not add-extra)))
              (unless rejected-before
                (fuzz-assert (<= (length parents) (length (bl.ser:transaction-inputs tx)))))))
          (if (consume-bool fdp)
              (bl.net:txdownload-add-tx-announcement mgr peer (bl.ser:transaction-hash tx) nil
                                                     (tdm-seconds time))
              (bl.net:txdownload-add-tx-announcement mgr peer (bl.ser:transaction-wtxid tx) t
                                                     (tdm-seconds time)))
          ;; Nothing requested is already had -- the reconsiderable filter
          ;; excepted, which may hold an orphan's low-feerate parent.
          (loop for (hash . wtxidp) in (bl.net:txdownload-get-requests-to-send
                                        mgr peer (tdm-seconds time))
                do (fuzz-assert (not (bl.net:txdownload-already-have-tx-p mgr hash wtxidp nil))))
          (tdm-impl-received-tx mgr peer tx)
          (bl.net:txdownload-received-not-found mgr peer (list (bl.ser:transaction-wtxid tx)))
          (let* ((expect-work (bl.net:txdownload-have-more-work mgr peer))
                 (orphan (bl.net:txdownload-get-tx-to-reconsider mgr peer)))
            (when orphan
              (fuzz-assert expect-work)
              (fuzz-assert (bl.net:txdownload-already-have-tx-p
                            mgr (bl.ser:transaction-wtxid orphan) t nil))
              ;; Presumably validated: "missing inputs" keeps it in the
              ;; orphanage for later iterations (:420-425).
              (bl.net:txdownload-mempool-rejected-tx mgr orphan :missing-input peer
                                                     (consume-bool fdp))))))
      (setf time (tdm-step-time fdp time)))
    (tdm-check-invariants mgr)
    (tdm-disconnect-everybody mgr)))
