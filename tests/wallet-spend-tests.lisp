(in-package #:bitcoin-lisp.tests)

;;; Wallet P4 tests: spending (docs/wallet-plan.md §5 P4).
;;;
;;; Unit layer: CFeeRate/FormatMoney/dust arithmetic, the waste metric
;;; (Core coinselector_tests.cpp waste_test ported with its exact constants
;;; and formula-derived expectations — the file has no literal vector
;;; tables to machine-extract; every expected value below is COMPUTED from
;;; the same arithmetic Core computes it from), BnB / Knapsack / SRD
;;; behavior incl. Core's bnb max-weight case, change-target bounds, and
;;; RNG determinism (all randomized paths run under a bound *wallet-rng*).
;;;
;;; Regtest layer (reuses the %wc-* fixtures): fund -> sendtoaddress with
;;; change -> mine -> balances reconcile exactly; SFFO single and
;;; multi-recipient with the first-recipient-pays-remainder rule;
;;; dust-change discarded to fee; sendall sweep; fundrawtransaction +
;;; signrawtransactionwithwallet round trip; watch-only partial signing;
;;; anti-fee-sniping locktime; RBF-default sequences; the built tx
;;; round-trips our own script verifier; maxtxfee and weight caps;
;;; rebroadcast machinery.

(def-suite wallet-spend-tests
  :description "Wallet P4: coin selection, spending, signing, rebroadcast"
  :in :bitcoin-lisp-tests)

(in-suite wallet-spend-tests)

;;; --- Helpers ---

(defconstant +ws-coin+ 100000000)
(defconstant +ws-cent+ 1000000)

(defvar *ws-txid-counter* 0)

(defun %ws-txid ()
  "A unique fake txid."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (n (incf *ws-txid-counter*)))
    (setf (aref v 0) (logand n 255)
          (aref v 1) (logand (ash n -8) 255)
          (aref v 2) (logand (ash n -16) 255))
    v))

(defun %ws-coin (value &key (fee 0) (ltf 0) (input-bytes 148))
  "A synthetic wallet-coin like coinselector_tests' add_coin(value, ...,
fee, long_term_fee): input_bytes 148, fee/effective-value set, long-term
fee patched afterwards."
  (let ((coin (bitcoin-lisp.rpc::make-wallet-coin
               :txid (%ws-txid) :index 0
               :output (bitcoin-lisp.serialization:make-tx-out
                        :value value
                        :script-pubkey (make-array 0 :element-type '(unsigned-byte 8)))
               :depth 1 :solvable t :safe t
               :input-bytes input-bytes
               :fee fee :effective-value (- value fee))))
    (setf (bitcoin-lisp.rpc::wallet-coin-long-term-fee coin) ltf)
    coin))

(defun %ws-group (coin &key sffo)
  "One-coin OutputGroup preserving the coin's pre-set long-term fee (Core's
add_coin comment: group.Insert overwrites long_term_fee, set it after)."
  (let ((group (bitcoin-lisp.rpc::make-out-group :subtract-fee-outputs sffo))
        (ltf (bitcoin-lisp.rpc::wallet-coin-long-term-fee coin)))
    (bitcoin-lisp.rpc::out-group-insert group coin 0 0)
    (setf (bitcoin-lisp.rpc::wallet-coin-long-term-fee coin) ltf)
    (setf (bitcoin-lisp.rpc::out-group-long-term-fee group) ltf)
    group))

(defun %ws-groups (specs &key sffo)
  "SPECS: list of (value &key fee ltf input-bytes) -> list of out-groups."
  (mapcar (lambda (spec)
            (%ws-group (apply #'%ws-coin (if (listp spec) spec (list spec)))
                       :sffo sffo))
          specs))

(defun %ws-add-to-result (result value fee ltf)
  (bitcoin-lisp.rpc::sel-result-add-group
   result (%ws-group (%ws-coin value :fee fee :ltf ltf))))

(defun %ws-result-values (result)
  (sort (mapcar (lambda (coin)
                  (bitcoin-lisp.serialization:tx-out-value
                   (bitcoin-lisp.rpc::wallet-coin-output coin)))
                (bitcoin-lisp.rpc::sel-result-inputs result))
        #'<))

;;; --- CFeeRate / FormatMoney / dust arithmetic ---

(test ws-feerate-fee
  "Core CFeeRate::GetFee at d3056bc: EvaluateFeeUp — ceil(rate*size/1000),
always rounded UP (feerate.cpp:20-27, feefrac.h)."
  (is (= 0 (bitcoin-lisp.rpc::%feerate-fee 1000 0)))
  (is (= 1 (bitcoin-lisp.rpc::%feerate-fee 1000 1)))
  (is (= 1 (bitcoin-lisp.rpc::%feerate-fee 1 999)))     ; ceil(0.999)
  (is (= 1 (bitcoin-lisp.rpc::%feerate-fee 1 1000)))
  (is (= 2 (bitcoin-lisp.rpc::%feerate-fee 1 1001)))    ; ceil(1.001)
  (is (= 141 (bitcoin-lisp.rpc::%feerate-fee 1000 141)))
  (is (= 1410 (bitcoin-lisp.rpc::%feerate-fee 10000 141)))
  (is (= 423 (bitcoin-lisp.rpc::%feerate-fee 3000 141)))  ; exact
  ;; Round-up discriminator: truncation would give 422 (422.859 -> 423 up).
  (is (= 423 (bitcoin-lisp.rpc::%feerate-fee 2999 141)))
  ;; The 1300 sat/kvB case from the review: per-part round-up sums (54+40+88
  ;; = 182... under truncation the parts sum BELOW the whole ceil(183.3);
  ;; under round-up every part covers its share and the whole is 184 <= sum
  ;; of any parts covering >= its size).
  (is (= 184 (bitcoin-lisp.rpc::%feerate-fee 1300 141)))
  (is (<= (bitcoin-lisp.rpc::%feerate-fee 1300 141)
          (+ (bitcoin-lisp.rpc::%feerate-fee 1300 41)
             (bitcoin-lisp.rpc::%feerate-fee 1300 31)
             (bitcoin-lisp.rpc::%feerate-fee 1300 69))))
  (is (= 204 (bitcoin-lisp.rpc::%feerate-fee 3000 68)))   ; exact
  (is (= 0 (bitcoin-lisp.rpc::%feerate-fee 0 1000))))

(test ws-format-money
  "Core FormatMoney: trailing-zero trim keeping at least two decimals."
  (is (string= "0.00" (bitcoin-lisp.rpc::%format-money 0)))
  (is (string= "1.00" (bitcoin-lisp.rpc::%format-money 100000000)))
  (is (string= "1.50" (bitcoin-lisp.rpc::%format-money 150000000)))
  (is (string= "0.001" (bitcoin-lisp.rpc::%format-money 100000)))
  (is (string= "0.10" (bitcoin-lisp.rpc::%format-money 10000000)))
  (is (string= "0.00000123" (bitcoin-lisp.rpc::%format-money 123)))
  (is (string= "1.23456789" (bitcoin-lisp.rpc::%format-money 123456789)))
  (is (string= "-0.50" (bitcoin-lisp.rpc::%format-money -50000000))))

(test ws-dust-threshold-at-rate
  "The parameterized dust threshold agrees with the validation layer's
fixed-rate version at the 3000 sat/kvB dust relay rate."
  (let ((p2wpkh (concatenate '(vector (unsigned-byte 8))
                             #(#x00 #x14) (make-array 20 :initial-element 7)))
        (p2pkh (concatenate '(vector (unsigned-byte 8))
                            #(#x76 #xa9 #x14) (make-array 20 :initial-element 7)
                            #(#x88 #xac)))
        (op-return (coerce #(#x6a #x04 1 2 3 4) '(vector (unsigned-byte 8)))))
    (is (= (bitcoin-lisp.validation:dust-threshold p2wpkh)
           (bitcoin-lisp.rpc::%dust-threshold-at-rate p2wpkh 3000)))
    (is (= (bitcoin-lisp.validation:dust-threshold p2pkh)
           (bitcoin-lisp.rpc::%dust-threshold-at-rate p2pkh 3000)))
    (is (= 294 (bitcoin-lisp.rpc::%dust-threshold-at-rate p2wpkh 3000)))
    (is (= 546 (bitcoin-lisp.rpc::%dust-threshold-at-rate p2pkh 3000)))
    (is (= 0 (bitcoin-lisp.rpc::%dust-threshold-at-rate op-return 3000)))))

(test ws-feerate-from-value
  "AmountFromValue(fee_rate, decimals=3): sat/vB to sat/kvB, 3 decimals max."
  (is (= 10000 (bitcoin-lisp.rpc::%feerate-from-value 10)))
  (is (= 1100 (bitcoin-lisp.rpc::%feerate-from-value "1.1")))
  (is (= 1001 (bitcoin-lisp.rpc::%feerate-from-value "1.001")))
  (is (= 25000 (bitcoin-lisp.rpc::%feerate-from-value 25)))
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::%feerate-from-value "1.0001")))

(test ws-amount-sub-satoshi-rejected
  "AmountFromValue rejects sub-satoshi precision (Core parses the decimal
text exactly and errors on >8 fraction digits); legit amounts still parse."
  (is (= 500000 (bitcoin-lisp.rpc::%amount-from-value 0.005)))
  (is (= 1 (bitcoin-lisp.rpc::%amount-from-value 1/100000000)))
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::%amount-from-value 1/1000000000))        ; 0.1 sat exact
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::%amount-from-value 1.23456789012d0))     ; sub-sat double
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::%amount-from-value 0.000000001d0)))      ; 0.1 sat double

(test ws-positional-bool-plumbing
  "Explicit false survives JSON parsing as the +json-false+ sentinel at
top-level positional positions (distinguishable from null/omitted, Core's
isNull semantics); nested objects/arrays keep the historical present-p
folding; the %positional-bool helpers decode all three states."
  (multiple-value-bind (type method params)
      (bitcoin-lisp.rpc::parse-json-rpc-request
       "{\"method\":\"x\",\"params\":[true,false,null,{\"a\":false,\"b\":true},[false]],\"id\":1}")
    (is (eq type :single))
    (is (string= method "x"))
    (is (eq t (first params)))
    (is (eq bitcoin-lisp.rpc:+json-false+ (second params)))
    (is (null (third params)))
    (let ((obj (fourth params)))
      (multiple-value-bind (a present) (gethash "a" obj)
        (is (null a))
        (is (eq t present)))
      (is (eq t (gethash "b" obj))))
    (is (equal '(nil) (fifth params))))
  (is (null (bitcoin-lisp.rpc::%positional-bool
             bitcoin-lisp.rpc:+json-false+)))
  (is (null (bitcoin-lisp.rpc::%positional-bool nil)))
  (is (eq t (bitcoin-lisp.rpc::%positional-bool t)))
  (is (eq t (bitcoin-lisp.rpc::%positional-bool-or nil t)))
  (is (null (bitcoin-lisp.rpc::%positional-bool-or
             bitcoin-lisp.rpc:+json-false+ t)))
  (is (eq t (bitcoin-lisp.rpc::%positional-bool-or t t))))

;;; --- RNG determinism ---

(test ws-rng-determinism
  (let ((a (bitcoin-lisp.rpc::make-wrng 42))
        (b (bitcoin-lisp.rpc::make-wrng 42)))
    (is (equal (loop repeat 16 collect (bitcoin-lisp.rpc::wrng-next64 a))
               (loop repeat 16 collect (bitcoin-lisp.rpc::wrng-next64 b))))
    (is (equal (bitcoin-lisp.rpc::wrng-shuffle
                (bitcoin-lisp.rpc::make-wrng 7) '(1 2 3 4 5 6 7 8))
               (bitcoin-lisp.rpc::wrng-shuffle
                (bitcoin-lisp.rpc::make-wrng 7) '(1 2 3 4 5 6 7 8))))
    (loop repeat 200
          do (is (< (bitcoin-lisp.rpc::wrng-randrange a 10) 10)))))

(test ws-generate-change-target
  "Core GenerateChangeTarget: fixed floor for small payments, else
change_fee + [CHANGE_LOWER, min(2*payment, CHANGE_UPPER))."
  (let ((rng (bitcoin-lisp.rpc::make-wrng 1)))
    ;; payment <= CHANGE_LOWER/2 -> exactly change_fee + CHANGE_LOWER
    (is (= 50030 (bitcoin-lisp.rpc::generate-change-target 25000 30 rng)))
    (loop repeat 100
          do (let ((target (bitcoin-lisp.rpc::generate-change-target 100000 30 rng)))
               (is (<= (+ 30 50000) target))
               (is (< target (+ 30 200000)))))
    (loop repeat 100
          do (let ((target (bitcoin-lisp.rpc::generate-change-target
                            (* 10 +ws-coin+) 0 rng)))
               (is (<= 50000 target))
               (is (< target 1000000))))))

;;; --- Waste metric (Core coinselector_tests.cpp waste_test) ---

(test ws-waste-metric
  "RecalculateWaste under Core's waste_test scenarios; expectations are the
same formulas Core asserts."
  (let* ((fee 100) (min-viable-change 300) (change-cost 125) (change-fee 30)
         (fee-diff 40) (in-amt (* 3 +ws-coin+)) (target (* 2 +ws-coin+))
         (excess 80) (exact-target (- in-amt (* fee 2))))
    (flet ((waste (result-target coin-fee coin-ltf &key (cost change-cost))
             (let ((result (bitcoin-lisp.rpc::make-sel-result
                            :target result-target :algo :manual)))
               (%ws-add-to-result result (* 1 +ws-coin+) coin-fee coin-ltf)
               (%ws-add-to-result result (* 2 +ws-coin+) coin-fee coin-ltf)
               (bitcoin-lisp.rpc::sel-result-recalculate-waste
                result min-viable-change cost change-fee)
               (bitcoin-lisp.rpc::sel-result-waste result))))
      ;; Waste with change: change cost + fee delta.
      (let ((waste1 (waste target fee (- fee fee-diff))))
        (is (= (+ (* 2 fee-diff) change-cost) waste1))
        ;; Higher fee, same long-term fee: greater waste.
        (is (> (waste target (* 2 fee) (- fee fee-diff)) waste1))
        ;; Long term fee above fee: less waste.
        (let ((waste3 (waste target fee (+ fee fee-diff))))
          (is (= (+ (* -2 fee-diff) change-cost) waste3))
          (is (< waste3 waste1))))
      ;; Waste without change: excess + fee delta.
      (let ((waste-nc1 (waste (- exact-target excess) fee (- fee fee-diff))))
        (is (= (+ (* 2 fee-diff) excess) waste-nc1))
        (let ((waste-nc2 (waste (- exact-target excess) fee (+ fee fee-diff))))
          (is (= (+ (* -2 fee-diff) excess) waste-nc2))
          (is (< waste-nc2 waste-nc1))))
      ;; fee == long term fee: change cost only / excess only / zero.
      (is (= change-cost (waste target fee fee)))
      (is (= excess (waste (- exact-target excess) fee fee)))
      (is (= 0 (waste exact-target fee fee)))
      ;; (fee - ltf) == -cost_of_change, no excess: zero.
      (is (= 0 (waste target fee (+ fee fee-diff) :cost (* 2 fee-diff))))
      ;; (fee - ltf) == -excess, no change cost: zero.
      (is (= 0 (waste (- exact-target (* 2 fee-diff)) fee (+ fee fee-diff))))
      ;; Negative waste: ltf > fee, selected == target.
      (is (= (* -2 fee-diff) (waste exact-target fee (+ fee fee-diff))))
      ;; Negative waste with change: change_cost < -(fee delta).
      (let ((large-fee-diff 90))
        (is (= (+ (* -2 large-fee-diff) change-cost)
               (waste target fee (+ fee large-fee-diff))))
        (is (= -55 (+ (* -2 large-fee-diff) change-cost)))))))

;;; --- BnB ---

(test ws-bnb-basics
  (let ((max-weight bitcoin-lisp.validation:+max-standard-tx-weight+))
    ;; Exact single match.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::select-coins-bnb
         (%ws-groups (list (* 1 +ws-cent+) (* 2 +ws-cent+) (* 3 +ws-cent+)))
         (* 1 +ws-cent+) 0 max-weight)
      (is (not (null result)))
      (is (equal (list (* 1 +ws-cent+)) (%ws-result-values result))))
    ;; Exact multi-coin: 5 + 3 + 2 = 10.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::select-coins-bnb
         (%ws-groups (list (* 5 +ws-cent+) (* 3 +ws-cent+) (* 2 +ws-cent+)))
         (* 10 +ws-cent+) 0 max-weight)
      (is (not (null result)))
      (is (equal (list (* 2 +ws-cent+) (* 3 +ws-cent+) (* 5 +ws-cent+))
                 (%ws-result-values result))))
    ;; No exact combination within a zero cost-of-change window.
    (multiple-value-bind (result error)
        (bitcoin-lisp.rpc::select-coins-bnb
         (%ws-groups (list (* 5 +ws-cent+) (* 3 +ws-cent+) (* 2 +ws-cent+)))
         (* 4 +ws-cent+) 0 max-weight)
      (is (null result))
      (is (null error)))
    ;; The cost-of-change window: value within [target, target+coc].
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::select-coins-bnb
         (%ws-groups (list (* 10 +ws-cent+)))
         (- (* 10 +ws-cent+) 500) 1000 max-weight)
      (is (not (null result))))
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::select-coins-bnb
         (%ws-groups (list (* 10 +ws-cent+)))
         (- (* 10 +ws-cent+) 500) 100 max-weight)
      (is (null result)))
    ;; Insufficient funds.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::select-coins-bnb
         (%ws-groups (list (* 1 +ws-cent+))) (* 2 +ws-cent+) 0 max-weight)
      (is (null result)))
    ;; Waste minimization: target 6 with {5,4,3,2} picks the exact 4+2.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::select-coins-bnb
         (%ws-groups (list (* 5 +ws-cent+) (* 4 +ws-cent+) (* 3 +ws-cent+)
                           (* 2 +ws-cent+)))
         (* 6 +ws-cent+) (* 10 +ws-cent+) max-weight)
      (is (not (null result)))
      (is (= (* 6 +ws-cent+)
             (bitcoin-lisp.rpc::sel-result-selected-value result))))))

(test ws-bnb-max-weight
  "Core bnb_search_test's max-weight scenario at feerate 5000 / SFFO
grouping: the oversized 5-cent coin first forces the max-weight error, and
after adding a normal 5-cent coin BnB finds {8, 5, 3}."
  (flet ((spec (cents input-bytes)
           (list (* cents +ws-cent+)
                 :fee (bitcoin-lisp.rpc::%feerate-fee 5000 input-bytes)
                 :ltf 0
                 :input-bytes input-bytes)))
    (let ((max-weight bitcoin-lisp.validation:+max-standard-tx-weight+)
          (target (* 16 +ws-cent+)))
      (multiple-value-bind (result error)
          (bitcoin-lisp.rpc::select-coins-bnb
           (%ws-groups (list (spec 10 68) (spec 9 68) (spec 8 68)
                             (spec 5 bitcoin-lisp.validation:+max-standard-tx-weight+)
                             (spec 3 68) (spec 1 68))
                       :sffo t)
           target 0 max-weight)
        (is (null result))
        (is (search "The inputs size exceeds the maximum weight" error)))
      (multiple-value-bind (result)
          (bitcoin-lisp.rpc::select-coins-bnb
           (%ws-groups (list (spec 10 68) (spec 9 68) (spec 8 68)
                             (spec 5 bitcoin-lisp.validation:+max-standard-tx-weight+)
                             (spec 3 68) (spec 1 68) (spec 5 68))
                       :sffo t)
           target 0 max-weight)
        (is (not (null result)))
        (is (equal (list (* 3 +ws-cent+) (* 5 +ws-cent+) (* 8 +ws-cent+))
                   (%ws-result-values result)))))))

;;; --- Knapsack ---

(test ws-knapsack-basics
  (let ((rng (bitcoin-lisp.rpc::make-wrng 99))
        (max-weight bitcoin-lisp.validation:+max-standard-tx-weight+)
        (change +ws-cent+))
    ;; Empty pool.
    (is (null (bitcoin-lisp.rpc::knapsack-solver '() +ws-cent+ change
                                                 rng max-weight)))
    ;; Exact single match short-circuits.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::knapsack-solver
         (%ws-groups (list (* 1 +ws-cent+) (* 5 +ws-cent+)))
         (* 1 +ws-cent+) change rng max-weight)
      (is (equal (list (* 1 +ws-cent+)) (%ws-result-values result))))
    ;; Sum of lower coins == target -> all of them.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::knapsack-solver
         (%ws-groups (list (* 1 +ws-cent+) (* 2 +ws-cent+)))
         (* 3 +ws-cent+) change rng max-weight)
      (is (equal (list (* 1 +ws-cent+) (* 2 +ws-cent+))
                 (%ws-result-values result))))
    ;; Not enough smaller coins -> smallest larger coin.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::knapsack-solver
         (%ws-groups (list (* 5 +ws-cent+) (* 10 +ws-cent+) (* 20 +ws-cent+)))
         (* 6 +ws-cent+) change rng max-weight)
      (is (equal (list (* 10 +ws-cent+)) (%ws-result-values result))))
    ;; Nothing reaches the target at all.
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::knapsack-solver
         (%ws-groups (list (* 1 +ws-cent+))) (* 2 +ws-cent+) change
         rng max-weight)
      (is (null result)))))

;;; --- SRD ---

(test ws-srd-basics
  (let ((max-weight bitcoin-lisp.validation:+max-standard-tx-weight+))
    ;; Sum exactly covers target + CHANGE_LOWER -> success (all coins).
    (multiple-value-bind (result)
        (bitcoin-lisp.rpc::select-coins-srd
         (%ws-groups (make-list 10 :initial-element (* 1 +ws-cent+)))
         (- (* 10 +ws-cent+) 50000) 0
         (bitcoin-lisp.rpc::make-wrng 3) max-weight)
      (is (not (null result)))
      (is (= (* 10 +ws-cent+)
             (bitcoin-lisp.rpc::sel-result-selected-value result))))
    ;; One satoshi short of target + CHANGE_LOWER -> failure.
    (multiple-value-bind (result error)
        (bitcoin-lisp.rpc::select-coins-srd
         (%ws-groups (make-list 10 :initial-element (* 1 +ws-cent+)))
         (- (* 10 +ws-cent+) 49999) 0
         (bitcoin-lisp.rpc::make-wrng 3) max-weight)
      (is (null result))
      (is (null error)))
    ;; Deterministic under a fixed seed.
    (let ((groups (%ws-groups (list (* 1 +ws-cent+) (* 2 +ws-cent+)
                                    (* 3 +ws-cent+) (* 4 +ws-cent+)
                                    (* 5 +ws-cent+)))))
      (multiple-value-bind (a)
          (bitcoin-lisp.rpc::select-coins-srd
           groups (* 2 +ws-cent+) 0 (bitcoin-lisp.rpc::make-wrng 11) max-weight)
        (multiple-value-bind (b)
            (bitcoin-lisp.rpc::select-coins-srd
             groups (* 2 +ws-cent+) 0 (bitcoin-lisp.rpc::make-wrng 11) max-weight)
          (is (equal (%ws-result-values a) (%ws-result-values b))))))))

;;; --- Regtest end-to-end ---

(defun %ws-mempool-tx (node txid)
  (bitcoin-lisp.rpc::with-node-lock (node)
    (let* ((mempool (bitcoin-lisp::node-mempool node))
           (entry (and mempool (bitcoin-lisp.mempool:mempool-get mempool txid))))
      (and entry (bitcoin-lisp.mempool:mempool-entry-transaction entry)))))

(defun %ws-tx-fee (node wallet tx)
  "inputs - outputs, resolved through the wallet/UTXO/mempool coins map."
  (bitcoin-lisp.rpc::with-node-lock (node)
    (bitcoin-lisp.rpc::with-wallet-lock (wallet)
      (let ((coins (bitcoin-lisp.rpc::%wallet-input-coins node wallet tx))
            (in 0))
        (bitcoin-lisp.serialization:dovector
            (input (bitcoin-lisp.serialization:transaction-inputs tx))
          (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                 (entry (gethash (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                                       (bitcoin-lisp.serialization:outpoint-index prevout))
                                 coins)))
            (is (not (null entry)))
            (incf in (second entry))))
        (- in
           (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs tx)
                   :key #'bitcoin-lisp.serialization:tx-out-value
                   :initial-value 0))))))

(defun %ws-est-vsize (node wallet tx)
  "The estimator's max signed vsize for TX (all inputs wallet-owned)."
  (bitcoin-lisp.rpc::with-node-lock (node)
    (bitcoin-lisp.rpc::with-wallet-lock (wallet)
      (let ((txouts
              (map 'list
                   (lambda (input)
                     (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                            (txout (bitcoin-lisp.rpc::%wallet-input-txout
                                    node wallet
                                    (bitcoin-lisp.serialization:outpoint-hash prevout)
                                    (bitcoin-lisp.serialization:outpoint-index prevout))))
                       (cons (bitcoin-lisp.serialization:tx-out-script-pubkey txout)
                             nil)))
                   (bitcoin-lisp.serialization:transaction-inputs tx))))
        (bitcoin-lisp.rpc::%max-signed-tx-size wallet nil tx txouts)))))

(defun %ws-verify-ok-p (node wallet tx)
  (bitcoin-lisp.rpc::with-node-lock (node)
    (bitcoin-lisp.rpc::with-wallet-lock (wallet)
      (let ((coins (bitcoin-lisp.rpc::%wallet-input-coins node wallet tx)))
        (nth-value 0 (bitcoin-lisp.rpc::%verify-tx-scripts tx coins))))))

(defun %ws-fund-wallet (node &key (blocks 1))
  "Create wallet \"w\", mine BLOCKS coinbases to it, mature them. Returns
(values wallet address)."
  (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
  (let* ((wallet (%wc-wallet node "w"))
         (address (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32"))))
    (dotimes (i blocks) (%wc-mine node 1 address))
    (%wc-mine node 101 (%wc-optrue-address))
    (values wallet address)))

(test ws-sendtoaddress-e2e
  "sendtoaddress: exact fee (= feerate x estimated vsize), internal change,
RBF sequences, anti-fee-sniping locktime, script-verifier round trip, and
balances that reconcile to the satoshi before and after confirmation."
  (%with-wallet-chain-node (node "ws-send")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (is (= 50.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '())))
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 12345))
             (dest (%wc-optrue-address))
             (dest-spk (nth-value 1 (bitcoin-lisp.crypto:decode-address
                                     dest :regtest)))
             (tip-height 102)
             (txid-hex (bitcoin-lisp.rpc::rpc-sendtoaddress
                        node (list dest 1 nil nil nil nil nil nil nil 10)))
             (txid (bitcoin-lisp.rpc::parse-hex-hash txid-hex))
             (tx (%ws-mempool-tx node txid)))
        (is (not (null tx)))
        (let* ((outputs (bitcoin-lisp.serialization:transaction-outputs tx))
               (fee (%ws-tx-fee node wallet tx))
               (est-vsize (%ws-est-vsize node wallet tx)))
          (is (= 2 (length outputs)))
          ;; Exact fee: feerate 10 sat/vB x estimated max signed vsize.
          (is (= fee (bitcoin-lisp.rpc::%feerate-fee 10000 est-vsize)))
          ;; Actual signed weight never exceeds the estimate.
          (is (<= (bitcoin-lisp.serialization:transaction-weight tx)
                  (nth-value 1 (%ws-est-vsize node wallet tx))))
          ;; Recipient output exact; the other output is OUR change.
          (let ((pay (find dest-spk (coerce outputs 'list)
                           :key #'bitcoin-lisp.serialization:tx-out-script-pubkey
                           :test #'equalp)))
            (is (not (null pay)))
            (is (= 100000000 (bitcoin-lisp.serialization:tx-out-value pay)))
            (let ((change (find pay (coerce outputs 'list) :test-not #'eq)))
              (is (bitcoin-lisp.rpc::wallet-is-mine
                   wallet (bitcoin-lisp.serialization:tx-out-script-pubkey change)))
              ;; Change address is an internal-chain (ischange) address.
              (let* ((change-addr (bitcoin-lisp.rpc::%script->address
                                   (bitcoin-lisp.serialization:tx-out-script-pubkey change)
                                   :regtest))
                     (info (bitcoin-lisp.rpc::rpc-getaddressinfo
                            node (list change-addr))))
                (is (eq t (%aval "ischange" info))))))
          ;; RBF default sequences.
          (bitcoin-lisp.serialization:dovector
              (input (bitcoin-lisp.serialization:transaction-inputs tx))
            (is (= #xFFFFFFFD (bitcoin-lisp.serialization:tx-in-sequence input))))
          ;; Anti-fee-sniping: locktime at (or up to 99 below) the tip.
          (let ((locktime (bitcoin-lisp.serialization:transaction-lock-time tx)))
            (is (<= (- tip-height 99) locktime tip-height)))
          ;; The committed tx verifies against the exact spent scripts.
          (is (%ws-verify-ok-p node wallet tx))
          ;; Balance before confirmation: change is trusted (own zero-conf).
          (is (= (/ (- 5000000000 100000000 fee) 100000000.0d0)
                 (bitcoin-lisp.rpc::rpc-getbalance node '())))
          ;; Confirm; balances identical, gettransaction agrees on the fee.
          (%wc-mine node 1 (%wc-optrue-address))
          (is (= (/ (- 5000000000 100000000 fee) 100000000.0d0)
                 (bitcoin-lisp.rpc::rpc-getbalance node '())))
          (let ((gettx (%wc-gettx node txid)))
            (is (= 1 (%aval "confirmations" gettx)))
            (is (= (/ (- fee) 100000000.0d0) (%aval "fee" gettx)))))))))

(test ws-sffo-single-and-multi
  "Subtract-fee-from-outputs: single recipient pays exactly the fee;
multi-recipient splits it with the first (in built-tx order) paying the
remainder."
  (%with-wallet-chain-node (node "ws-sffo")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 777))
             (dest (%wc-optrue-address))
             (dest-spk (nth-value 1 (bitcoin-lisp.crypto:decode-address
                                     dest :regtest))))
        ;; Single-recipient SFFO.
        (let* ((txid (bitcoin-lisp.rpc::parse-hex-hash
                      (bitcoin-lisp.rpc::rpc-sendtoaddress
                       node (list dest 1 nil nil t nil nil nil nil 10))))
               (tx (%ws-mempool-tx node txid))
               (fee (%ws-tx-fee node wallet tx))
               (pay (find dest-spk
                          (coerce (bitcoin-lisp.serialization:transaction-outputs tx)
                                  'list)
                          :key #'bitcoin-lisp.serialization:tx-out-script-pubkey
                          :test #'equalp)))
          (is (not (null tx)))
          (is (= (- 100000000 fee)
                 (bitcoin-lisp.serialization:tx-out-value pay)))
          (is (= fee (bitcoin-lisp.rpc::%feerate-fee
                      10000 (%ws-est-vsize node wallet tx)))))
        ;; Multi-recipient SFFO through sendmany: fee split over both, one
        ;; recipient pays floor(fee/2)+rem, the other floor(fee/2).
        (let* ((redeem-2 (coerce #(#x51 #x51) '(vector (unsigned-byte 8)))) ; OP_TRUE OP_TRUE
               (dest2 (bitcoin-lisp.crypto:encode-p2sh-address
                       (bitcoin-lisp.crypto:hash160 redeem-2) :regtest))
               (dest2-spk (nth-value 1 (bitcoin-lisp.crypto:decode-address
                                        dest2 :regtest)))
               (txid (bitcoin-lisp.rpc::parse-hex-hash
                      (bitcoin-lisp.rpc::rpc-sendmany
                       node (list "" (list (cons dest 2) (cons dest2 1))
                                  nil nil (list dest dest2) nil nil nil 10))))
               (tx (%ws-mempool-tx node txid))
               (fee (%ws-tx-fee node wallet tx))
               (outputs (coerce (bitcoin-lisp.serialization:transaction-outputs tx)
                                'list))
               (pay1 (find dest-spk outputs
                           :key #'bitcoin-lisp.serialization:tx-out-script-pubkey
                           :test #'equalp))
               (pay2 (find dest2-spk outputs
                           :key #'bitcoin-lisp.serialization:tx-out-script-pubkey
                           :test #'equalp))
               (share (truncate fee 2))
               (remainder (rem fee 2)))
          (is (not (null tx)))
          (is (not (null pay1)))
          (is (not (null pay2)))
          (let ((v1 (bitcoin-lisp.serialization:tx-out-value pay1))
                (v2 (bitcoin-lisp.serialization:tx-out-value pay2)))
            ;; Sum reconciles exactly; the remainder lands on exactly one.
            (is (= (+ v1 v2) (- 300000000 fee)))
            (is (or (and (= v1 (- 200000000 share remainder))
                         (= v2 (- 100000000 share)))
                    (and (= v1 (- 200000000 share))
                         (= v2 (- 100000000 share remainder)))))))))))

(test ws-dust-change-to-fee
  "A remainder below the minimum viable change is discarded to fees: the
tx gets no change output and overpays exactly the remainder."
  (%with-wallet-chain-node (node "ws-dust")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 5))
             (dest (%wc-optrue-address))
             (amount-sat (- 5000000000 900))
             (txid (bitcoin-lisp.rpc::parse-hex-hash
                    (bitcoin-lisp.rpc::rpc-sendtoaddress
                     node (list dest (format nil "~D.~8,'0D"
                                             (truncate amount-sat 100000000)
                                             (mod amount-sat 100000000))
                                nil nil nil nil nil nil nil 1))))
             (tx (%ws-mempool-tx node txid)))
        (is (not (null tx)))
        (is (= 1 (length (bitcoin-lisp.serialization:transaction-outputs tx))))
        (is (= 900 (%ws-tx-fee node wallet tx)))
        (is (%ws-verify-ok-p node wallet tx))))))

(test ws-sendall-sweep
  "sendall sweeps every coin: fee = feerate x estimated size, single
output of total - fee, wallet empty afterwards."
  (%with-wallet-chain-node (node "ws-sendall")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 21))
             (dest (%wc-optrue-address))
             (result (bitcoin-lisp.rpc::rpc-sendall
                      node (list (list dest) nil nil 10)))
             (txid (bitcoin-lisp.rpc::parse-hex-hash (%aval "txid" result)))
             (tx (%ws-mempool-tx node txid)))
        (is (eq t (%aval "complete" result)))
        (is (not (null tx)))
        (is (= 2 (length (bitcoin-lisp.serialization:transaction-inputs tx))))
        (is (= 1 (length (bitcoin-lisp.serialization:transaction-outputs tx))))
        (let ((fee (%ws-tx-fee node wallet tx))
              (est (%ws-est-vsize node wallet tx)))
          (is (= fee (bitcoin-lisp.rpc::%feerate-fee 10000 est)))
          (is (= (- 10000000000 fee)
                 (bitcoin-lisp.serialization:tx-out-value
                  (aref (bitcoin-lisp.serialization:transaction-outputs tx) 0)))))
        (is (%ws-verify-ok-p node wallet tx))
        (%wc-mine node 1 (%wc-optrue-address))
        (is (= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '())))))))

(test ws-fundrawtransaction-sign-broadcast
  "fundrawtransaction on an externally-built raw tx adds change at the
requested feerate; signrawtransactionwithwallet completes it;
sendrawtransaction accepts it. Preset locktime/sequence survive."
  (%with-wallet-chain-node (node "ws-fund")
    (multiple-value-bind (wallet address) (%ws-fund-wallet node)
      (declare (ignore address))
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 31))
             (coins (bitcoin-lisp.rpc::with-wallet-lock (wallet)
                      (bitcoin-lisp.rpc::wallet-available-coins wallet)))
             (coin (first coins))
             (raw (bitcoin-lisp.serialization:make-transaction
                   :version 2
                   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                      :hash (bitcoin-lisp.rpc::wallet-coin-txid coin)
                                                      :index (bitcoin-lisp.rpc::wallet-coin-index coin))
                                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                    :sequence #xFFFFFFFE))
                   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                     :value 100000000
                                     :script-pubkey (%p2sh-optrue-spk)))
                   :lock-time 0))
             (funded (bitcoin-lisp.rpc::rpc-fundrawtransaction
                      node (list (bitcoin-lisp.crypto:bytes-to-hex
                                  (bitcoin-lisp.serialization:transaction-wire-bytes raw))
                                 '(("fee_rate" . 10)))))
             (fee-btc (%aval "fee" funded))
             (changepos (%aval "changepos" funded)))
        (is (member changepos '(0 1)))
        (is (> fee-btc 0))
        (let* ((funded-tx (bitcoin-lisp.serialization:parse-tx-payload
                           (bitcoin-lisp.crypto:hex-to-bytes (%aval "hex" funded)))))
          ;; Preset sequence and locktime preserved; no anti-fee-sniping.
          (is (zerop (bitcoin-lisp.serialization:transaction-lock-time funded-tx)))
          (is (= #xFFFFFFFE
                 (bitcoin-lisp.serialization:tx-in-sequence
                  (aref (bitcoin-lisp.serialization:transaction-inputs funded-tx) 0))))
          ;; Exact fee at 10 sat/vB over the estimator's size.
          (is (= (round (* fee-btc 100000000))
                 (bitcoin-lisp.rpc::%feerate-fee
                  10000 (%ws-est-vsize node wallet funded-tx)))))
        (let ((signed (bitcoin-lisp.rpc::rpc-signrawtransactionwithwallet
                       node (list (%aval "hex" funded)))))
          (is (eq t (%aval "complete" signed)))
          (let ((txid-hex (bitcoin-lisp.rpc::rpc-sendrawtransaction
                           node (list (%aval "hex" signed)))))
            (is (stringp txid-hex))
            (is (not (null (%ws-mempool-tx
                            node (bitcoin-lisp.rpc::parse-hex-hash txid-hex)))))))))))

(test ws-signraw-watch-only-partial
  "signrawtransactionwithwallet on a watch-only wallet returns
complete:false with Core's per-input errors array."
  (%with-wallet-chain-node (node "ws-watch")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (declare (ignore wallet))
      ;; Watch-only wallet from an xpub descriptor.
      (bitcoin-lisp.rpc::rpc-createwallet node '("wo" t t))
      (let* ((seed (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 7))
             (xprv (bitcoin-lisp.crypto:bip32-master-key seed :network :testnet))
             (xpub (bitcoin-lisp.crypto:bip32-serialize
                    (bitcoin-lisp.crypto:bip32-neuter xprv)))
             (desc (bitcoin-lisp.rpc::descriptor-add-checksum
                    (format nil "wpkh(~A/0/*)" xpub)))
             (request (make-hash-table :test 'equal)))
        (setf (gethash "desc" request) desc
              (gethash "timestamp" request) "now"
              (gethash "active" request) t)
        (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "wo"))
          (let ((results (bitcoin-lisp.rpc::rpc-importdescriptors
                          node (list (list request)))))
            (is (eq t (%aval "success" (first results))))))
        (let* ((wo-address (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "wo"))
                             (bitcoin-lisp.rpc::rpc-getnewaddress
                              node '("" "bech32"))))
               (bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 8))
               (fund-txid (bitcoin-lisp.rpc::parse-hex-hash
                           (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
                             (bitcoin-lisp.rpc::rpc-sendtoaddress
                              node (list wo-address 1 nil nil nil nil nil nil
                                         nil 10))))))
          (%wc-mine node 1 (%wc-optrue-address))
          ;; Find the funded outpoint.
          (let* ((fund-tx (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
                            (bitcoin-lisp.serialization:parse-tx-payload
                             (bitcoin-lisp.crypto:hex-to-bytes
                              (%aval "hex" (bitcoin-lisp.rpc::rpc-gettransaction
                                            node (list (bitcoin-lisp.rpc::hash-to-hex
                                                        fund-txid))))))))
                 (wo-spk (nth-value 1 (bitcoin-lisp.crypto:decode-address
                                       wo-address :regtest)))
                 (vout (position wo-spk
                                 (coerce (bitcoin-lisp.serialization:transaction-outputs
                                          fund-tx)
                                         'list)
                                 :key #'bitcoin-lisp.serialization:tx-out-script-pubkey
                                 :test #'equalp))
                 (spend (bitcoin-lisp.serialization:make-transaction
                         :version 2
                         :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                          :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                            :hash fund-txid :index vout)
                                          :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                          :sequence #xFFFFFFFD))
                         :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                           :value 90000000
                                           :script-pubkey (%p2sh-optrue-spk)))
                         :lock-time 0))
                 (result (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "wo"))
                           (bitcoin-lisp.rpc::rpc-signrawtransactionwithwallet
                            node (list (bitcoin-lisp.crypto:bytes-to-hex
                                        (bitcoin-lisp.serialization:transaction-wire-bytes
                                         spend)))))))
            (is (not (null vout)))
            (is (eq bitcoin-lisp.rpc:+json-false+ (%aval "complete" result)))
            (let ((errors (%aval "errors" result)))
              (is (= 1 (length errors)))
              (let ((entry (first errors)))
                (is (string= (bitcoin-lisp.rpc::hash-to-hex fund-txid)
                             (%aval "txid" entry)))
                (is (= vout (%aval "vout" entry)))
                (is (stringp (%aval "error" entry)))
                (is (search "no key" (%aval "error" entry)))
                (is (= #xFFFFFFFD (%aval "sequence" entry)))))))))))

(test ws-maxtxfee-and-weight-caps
  "The -maxtxfee rail refuses to build over-fee transactions; max_tx_weight
bounds are enforced with Core's messages."
  (%with-wallet-chain-node (node "ws-caps")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (declare (ignore wallet))
      (let ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 61))
            (dest (%wc-optrue-address)))
        ;; maxtxfee: a 10 sat/vB spend costs ~1400+ sats; cap at 100.
        (let ((bitcoin-lisp:*wallet-max-tx-fee* 100))
          (handler-case
              (progn (bitcoin-lisp.rpc::rpc-sendtoaddress
                      node (list dest 1 nil nil nil nil nil nil nil 10))
                     (fail "maxtxfee cap not enforced"))
            (bitcoin-lisp.rpc::rpc-error (e)
              (is (= -6 (bitcoin-lisp.rpc::rpc-error-code e)))
              (is (search "Fee exceeds maximum configured by user"
                          (bitcoin-lisp.rpc::rpc-error-message e))))))
        ;; Weight caps via send's max_tx_weight.
        (handler-case
            (progn (bitcoin-lisp.rpc::rpc-send
                    node (list (list (cons dest 1)) nil nil 10
                               '(("max_tx_weight" . 100))))
                   (fail "max_tx_weight lower bound not enforced"))
          (bitcoin-lisp.rpc::rpc-error (e)
            (is (search "Maximum transaction weight must be between"
                        (bitcoin-lisp.rpc::rpc-error-message e)))))
        (handler-case
            (progn (bitcoin-lisp.rpc::rpc-send
                    node (list (list (cons dest 1)) nil nil 10
                               '(("max_tx_weight" . 300))))
                   (fail "max_tx_weight cap not enforced"))
          (bitcoin-lisp.rpc::rpc-error (e)
            ;; The 300-weight budget dies in selection: no input fits.
            (is (search "maximum weight"
                        (bitcoin-lisp.rpc::rpc-error-message e)
                        :test #'char-equal))))))))

(test ws-fee-estimation-paths
  "Fallback fee drives fee estimation when the estimator has no data;
disabled fallback errors with Core's message; explicit feerates report
PayTxFee."
  (%with-wallet-chain-node (node "ws-fees")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 77))
            (dest (%wc-optrue-address)))
        ;; Fallback disabled (default): estimation failure.
        (handler-case
            (progn (bitcoin-lisp.rpc::rpc-sendtoaddress
                    node (list dest 1))
                   (fail "fallbackfee-disabled path not enforced"))
          (bitcoin-lisp.rpc::rpc-error (e)
            (is (= -6 (bitcoin-lisp.rpc::rpc-error-code e)))
            (is (search "Fallbackfee is disabled"
                        (bitcoin-lisp.rpc::rpc-error-message e)))))
        ;; Fallback enabled: 20 sat/vB fallback, verbose reports the reason.
        (let* ((bitcoin-lisp:*wallet-fallback-fee* 20000)
               (result (bitcoin-lisp.rpc::rpc-sendtoaddress
                        node (list dest 1 nil nil nil nil nil nil nil nil t)))
               (txid (bitcoin-lisp.rpc::parse-hex-hash (%aval "txid" result)))
               (tx (%ws-mempool-tx node txid)))
          (is (string= "Fallback fee" (%aval "fee_reason" result)))
          (is (not (null tx)))
          (is (= (%ws-tx-fee node wallet tx)
                 (bitcoin-lisp.rpc::%feerate-fee
                  20000 (%ws-est-vsize node wallet tx)))))
        ;; Explicit fee rate reports PayTxFee.
        (let ((result (bitcoin-lisp.rpc::rpc-sendtoaddress
                       node (list dest 1 nil nil nil nil nil nil nil 10 t))))
          (is (string= "PayTxFee set" (%aval "fee_reason" result))))))))

(test ws-anti-fee-sniping-direct
  "DiscourageFeeSniping: locktime = tip height, or backed off by up to 99
on the 1-in-10 branch; a FINAL sequence is an internal-bug error."
  (%with-wallet-chain-node (node "ws-snipe")
    (%ws-fund-wallet node)
    (let* ((tip-hash (bitcoin-lisp.storage:best-block-hash
                      (bitcoin-lisp::node-chain-state node)))
           (tip-height 102)
           (make-tx (lambda (sequence)
                      (bitcoin-lisp.serialization:make-transaction
                       :version 2
                       :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash (%ws-txid) :index 0)
                                        :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                        :sequence sequence))
                       :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                         :value 1000
                                         :script-pubkey (%p2sh-optrue-spk)))
                       :lock-time 0)))
           ;; Find seeds whose FIRST randrange(10) draw is nonzero / zero.
           (seed-tip (loop for seed from 1
                           when (plusp (bitcoin-lisp.rpc::wrng-randrange
                                        (bitcoin-lisp.rpc::make-wrng seed) 10))
                             return seed))
           (seed-back (loop for seed from 1
                            when (zerop (bitcoin-lisp.rpc::wrng-randrange
                                         (bitcoin-lisp.rpc::make-wrng seed) 10))
                              return seed)))
      (bitcoin-lisp.rpc::with-node-lock (node)
        ;; Non-backdated branch: locktime = tip height.
        (let ((tx (funcall make-tx #xFFFFFFFD)))
          (bitcoin-lisp.rpc::discourage-fee-sniping
           tx (bitcoin-lisp.rpc::make-wrng seed-tip) node tip-hash tip-height)
          (is (= tip-height
                 (bitcoin-lisp.serialization:transaction-lock-time tx))))
        ;; Backdated branch: exactly height - randrange(100), replayed.
        (let ((tx (funcall make-tx #xFFFFFFFE))
              (replay (bitcoin-lisp.rpc::make-wrng seed-back)))
          (bitcoin-lisp.rpc::wrng-randrange replay 10)
          (let ((expected (max 0 (- tip-height
                                    (bitcoin-lisp.rpc::wrng-randrange replay 100)))))
            (bitcoin-lisp.rpc::discourage-fee-sniping
             tx (bitcoin-lisp.rpc::make-wrng seed-back) node tip-hash tip-height)
            (is (= expected
                   (bitcoin-lisp.serialization:transaction-lock-time tx)))))
        ;; FINAL sequence violates the anti-fee-sniping contract.
        (signals bitcoin-lisp.rpc::rpc-error
          (bitcoin-lisp.rpc::discourage-fee-sniping
           (funcall make-tx #xFFFFFFFF)
           (bitcoin-lisp.rpc::make-wrng seed-tip) node tip-hash tip-height))))))

(test ws-nonfinal-sequence-when-rbf-off
  "With BIP125 signaling off, inputs carry MAX_SEQUENCE_NONFINAL."
  (%with-wallet-chain-node (node "ws-seq")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 4)))
        (bitcoin-lisp.rpc::with-node-lock (node)
          (bitcoin-lisp.rpc::with-wallet-lock (wallet)
            (multiple-value-bind (tx)
                (bitcoin-lisp.rpc::%create-transaction
                 node wallet
                 (list (bitcoin-lisp.rpc::make-recipient
                        :address (%wc-optrue-address)
                        :script (%p2sh-optrue-spk)
                        :amount 100000000))
                 nil
                 (bitcoin-lisp.rpc::make-wcc :signal-bip125-rbf nil
                                             :feerate 10000)
                 t)
              (is (not (null tx)))
              (bitcoin-lisp.serialization:dovector
                  (input (bitcoin-lisp.serialization:transaction-inputs tx))
                (is (= #xFFFFFFFE
                       (bitcoin-lisp.serialization:tx-in-sequence input)))))))))))

(test ws-rebroadcast-machinery
  "ResubmitWalletTransactions puts an evicted wallet tx back into the
mempool; the resend scheduler windows land in [12h, 36h)."
  (%with-wallet-chain-node (node "ws-resend")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 51))
             (dest (%wc-optrue-address))
             (txid (bitcoin-lisp.rpc::parse-hex-hash
                    (bitcoin-lisp.rpc::rpc-sendtoaddress
                     node (list dest 1 nil nil nil nil nil nil nil 10)))))
        (is (not (null (%ws-mempool-tx node txid))))
        (%wb-evict-tx node txid)
        (is (null (%ws-mempool-tx node txid)))
        ;; Non-forced resubmit skips fresh txs (received < 5 min after the
        ;; last block).
        (is (= 0 (bitcoin-lisp.rpc::wallet-resubmit-transactions
                  node wallet :relay nil)))
        (is (null (%ws-mempool-tx node txid)))
        ;; Forced resubmit (the wallet-load path) restores it.
        (is (= 1 (bitcoin-lisp.rpc::wallet-resubmit-transactions
                  node wallet :relay nil :force t)))
        (is (not (null (%ws-mempool-tx node txid))))
        (bitcoin-lisp.rpc::with-wallet-lock (wallet)
          (is (eq :in-mempool
                  (bitcoin-lisp.rpc::wallet-tx-state
                   (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid)))))
        ;; Resend scheduling window.
        (let* ((now (bitcoin-lisp.serialization:get-unix-time))
               (next (bitcoin-lisp.rpc::%wallet-default-next-resend
                      (bitcoin-lisp.rpc::make-wrng 9))))
          (is (<= (+ now (* 12 3600)) next))
          (is (< next (+ now (* 36 3600) 2))))))))

(test ws-send-rpc-e2e
  "send: commits and broadcasts by default; add_to_wallet=false returns
hex+psbt without committing."
  (%with-wallet-chain-node (node "ws-sendrpc")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 43))
             (dest (%wc-optrue-address))
             (result (bitcoin-lisp.rpc::rpc-send
                      node (list (list (cons dest 1)) nil nil 10 nil))))
        (is (eq t (%aval "complete" result)))
        (let ((txid (bitcoin-lisp.rpc::parse-hex-hash (%aval "txid" result))))
          (is (not (null (%ws-mempool-tx node txid))))
          (is (null (%aval "hex" result))))
        ;; add_to_wallet false: hex + psbt returned, nothing committed.
        (let* ((result2 (bitcoin-lisp.rpc::rpc-send
                         node (list (list (cons dest 1)) nil nil 10
                                    '(("add_to_wallet" . nil)))))
               (txid2 (bitcoin-lisp.rpc::parse-hex-hash (%aval "txid" result2))))
          (is (eq t (%aval "complete" result2)))
          (is (stringp (%aval "hex" result2)))
          (is (stringp (%aval "psbt" result2)))
          (is (null (%ws-mempool-tx node txid2)))
          (bitcoin-lisp.rpc::with-wallet-lock (wallet)
            (is (null (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid2))))
          ;; The returned PSBT parses and wraps the same unsigned skeleton.
          (let ((psbt (bitcoin-lisp.serialization:decode-psbt
                       (%aval "psbt" result2))))
            (is (= 1 (length (bitcoin-lisp.serialization:transaction-inputs
                              (bitcoin-lisp.serialization:psbt-tx psbt)))))))))))

;;; --- Adversarial-review regression tests (PR #293 review round) ---

(test ws-sffo-negative-data-output-rejected
  "B2: SFFO driving an OP_RETURN output negative is DUST (threshold 0) and
must error with Core's too-small-to-pay-the-fee message instead of
committing a mempool-invalid transaction as success."
  (%with-wallet-chain-node (node "ws-sffo-neg")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 13))
            (dest (%wc-optrue-address))
            (mempool-before
              (bitcoin-lisp.rpc::with-node-lock (node)
                (bitcoin-lisp.mempool::mempool-count
                 (bitcoin-lisp::node-mempool node)))))
        (handler-case
            (progn
              (bitcoin-lisp.rpc::rpc-send
               node (list (list (list (cons dest 1/1000))
                                (list (cons "data" "aa")))
                          nil nil 10
                          '(("subtract_fee_from_outputs" . (1)))))
              (fail "negative SFFO data output was not rejected"))
          (bitcoin-lisp.rpc::rpc-error (e)
            (is (search "too small to pay the fee"
                        (bitcoin-lisp.rpc::rpc-error-message e)))))
        ;; Nothing committed, nothing in the mempool, no coins spent.
        (is (= mempool-before
               (bitcoin-lisp.rpc::with-node-lock (node)
                 (bitcoin-lisp.mempool::mempool-count
                  (bitcoin-lisp::node-mempool node)))))
        (bitcoin-lisp.rpc::with-wallet-lock (wallet)
          (is (= 1 (hash-table-count
                    (bitcoin-lisp.rpc::wallet-map-wallet wallet)))))))))

(test ws-sendall-sweeps-reused-coins
  "B3: sendall on an avoid_reuse wallet still sweeps coins on previously
used addresses (Core AvailableCoins allow_used with sendall's default
coin control; excluding them would strand funds)."
  (%with-wallet-chain-node (node "ws-reuse")
    ;; avoid_reuse wallet.
    (bitcoin-lisp.rpc::rpc-createwallet node '("w" nil nil nil t))
    (let* ((wallet (%wc-wallet node "w"))
           (addr-a (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32")))
           (addr-b (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32")))
           (bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 17)))
      (is (bitcoin-lisp.rpc::wallet-flag-set-p
           wallet bitcoin-lisp.rpc::+wallet-flag-avoid-reuse+))
      ;; Fund A, spend from A (marks A previously-spent), then fund A again
      ;; (reused coin) and B (clean coin).
      (%wc-mine node 1 addr-a)
      (%wc-mine node 101 (%wc-optrue-address))
      (let ((sweep1 (bitcoin-lisp.rpc::rpc-sendall
                     node (list (list (%wc-optrue-address)) nil nil 2))))
        (is (eq t (%aval "complete" sweep1))))
      (%wc-mine node 1 (%wc-optrue-address))
      (is (bitcoin-lisp.rpc::wallet-address-previously-spent-p wallet addr-a))
      (%wc-mine node 1 addr-a)
      (%wc-mine node 1 addr-b)
      (%wc-mine node 101 (%wc-optrue-address))
      ;; The default balance hides the reused coin ...
      (is (= 50.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '())))
      ;; ... but sendall sweeps BOTH coins.
      (let* ((result (bitcoin-lisp.rpc::rpc-sendall
                      node (list (list (%wc-optrue-address)) nil nil 2)))
             (txid (bitcoin-lisp.rpc::parse-hex-hash (%aval "txid" result)))
             (tx (%ws-mempool-tx node txid)))
        (is (eq t (%aval "complete" result)))
        (is (not (null tx)))
        (is (= 2 (length (bitcoin-lisp.serialization:transaction-inputs tx)))))
      (%wc-mine node 1 (%wc-optrue-address))
      (is (= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '())))
      ;; getbalances "used" is empty too: everything left the wallet.
      (let ((balances (%wb-balances node)))
        (is (= 0.0d0 (%wb-aval "trusted" balances)))
        (is (= 0.0d0 (%wb-aval "used" balances)))))))

(test ws-explicit-false-positional-booleans
  "B4: explicit false on positional funds-policy booleans is honored.
replaceable=false turns RBF signaling off (nonfinal sequences); a
null-padded avoid_reuse keeps the wallet default while explicit true on a
wallet without the flag errors."
  (%with-wallet-chain-node (node "ws-bools")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (declare (ignore wallet))
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 23))
             (dest (%wc-optrue-address))
             (txid (bitcoin-lisp.rpc::parse-hex-hash
                    (bitcoin-lisp.rpc::rpc-sendtoaddress
                     node (list dest 1 nil nil nil
                                bitcoin-lisp.rpc:+json-false+
                                nil nil nil 10))))
             (tx (%ws-mempool-tx node txid)))
        (is (not (null tx)))
        (bitcoin-lisp.serialization:dovector
            (input (bitcoin-lisp.serialization:transaction-inputs tx))
          (is (= #xFFFFFFFE
                 (bitcoin-lisp.serialization:tx-in-sequence input)))))
      ;; avoid_reuse positional: null-padded (the normal way to reach
      ;; fee_rate at position 9) = wallet default -> fine on a wallet
      ;; without the flag; explicit true errors (Core GetAvoidReuseFlag).
      (is (numberp (bitcoin-lisp.rpc::rpc-getbalance
                    node (list "*" 0 nil nil))))
      (handler-case
          (progn (bitcoin-lisp.rpc::rpc-getbalance node (list "*" 0 nil t))
                 (fail "explicit avoid_reuse=true on a non-avoid_reuse wallet must error"))
        (bitcoin-lisp.rpc::rpc-error (e)
          (is (= -4 (bitcoin-lisp.rpc::rpc-error-code e)))))
      ;; createwallet: explicit descriptors=false is rejected; a null-padded
      ;; descriptors argument keeps the default (true) and succeeds.
      (handler-case
          (progn (bitcoin-lisp.rpc::rpc-createwallet
                  node (list "wleg" nil nil nil nil
                             bitcoin-lisp.rpc:+json-false+))
                 (fail "createwallet descriptors=false must be rejected"))
        (bitcoin-lisp.rpc::rpc-error (e)
          (is (search "no longer possible to create a legacy wallet"
                      (bitcoin-lisp.rpc::rpc-error-message e)))))
      (is (equal "wnull"
                 (%aval "name" (bitcoin-lisp.rpc::rpc-createwallet
                                node (list "wnull" nil nil nil nil nil))))))))

(test ws-taproot-spend-and-oddy-reload
  "B5: taproot end-to-end — the default wallet's tr() descriptor signs a
keypath spend, and an imported tr(WIF) with an ODD-Y internal key still
signs after a full unload/reload cycle (the persisted public descriptor
stores only the 32-byte x coordinate)."
  (%with-wallet-chain-node (node "ws-tr")
    (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
    (let* ((wallet (%wc-wallet node "w"))
           (addr-tr (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32m")))
           (bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 29))
           (dest (%wc-optrue-address)))
      ;; Fund the default 86h tr() descriptor and spend from it (BIP86
      ;; keypath through the wallet signer + script verifier).
      (%wc-mine node 1 addr-tr)
      (%wc-mine node 101 (%wc-optrue-address))
      (let* ((txid (bitcoin-lisp.rpc::parse-hex-hash
                    (bitcoin-lisp.rpc::rpc-sendtoaddress
                     node (list dest 1 nil nil nil nil nil nil nil 10))))
             (tx (%ws-mempool-tx node txid)))
        (is (not (null tx)))
        (is (%ws-verify-ok-p node wallet tx)))
      (%wc-mine node 1 (%wc-optrue-address))
      ;; Grind a private key whose point has ODD Y (03 prefix).
      (let* ((priv (loop for i from 1
                         for candidate = (let ((v (make-array 32 :element-type '(unsigned-byte 8)
                                                                 :initial-element 0)))
                                           (setf (aref v 31) (logand i 255)
                                                 (aref v 30) (ash i -8))
                                           v)
                         when (= 3 (aref (bitcoin-lisp.crypto:derive-public-key
                                          candidate :compressed t)
                                         0))
                           return candidate))
             (wif (bitcoin-lisp.crypto:private-key-to-wif
                   priv :network :testnet :compressed t))
             (desc (bitcoin-lisp.rpc::descriptor-add-checksum
                    (format nil "tr(~A)" wif)))
             (qx (bitcoin-lisp.coalton.interop:compute-tweaked-pubkey
                  (bitcoin-lisp.crypto:derive-xonly-pubkey priv)))
             (tr-address (bitcoin-lisp.crypto:segwit-address-encode
                          "bcrt" 1 qx))
             (request (make-hash-table :test 'equal)))
        (setf (gethash "desc" request) desc
              (gethash "timestamp" request) "now")
        (let ((results (bitcoin-lisp.rpc::rpc-importdescriptors
                        node (list (list request)))))
          (is (eq t (%aval "success" (first results)))))
        ;; Fund the imported odd-Y taproot address from the same wallet.
        (bitcoin-lisp.rpc::rpc-sendtoaddress
         node (list tr-address 1 nil nil nil nil nil nil nil 10))
        (%wc-mine node 1 (%wc-optrue-address))
        ;; Crash-close + reload: the imported descriptor comes back from its
        ;; persisted PUBLIC form (bare x-only hex).
        (bitcoin-lisp.rpc::rpc-unloadwallet node (list "w"))
        (bitcoin-lisp.rpc::rpc-loadwallet node (list "w"))
        (let ((reloaded (%wc-wallet node "w")))
          (is (not (null reloaded)))
          ;; Sweep everything — including the odd-Y tr(WIF) coin, which is
          ;; only signable when x-only keys are matched by X coordinate.
          (let* ((result (bitcoin-lisp.rpc::rpc-sendall
                          node (list (list dest) nil nil 10)))
                 (txid (bitcoin-lisp.rpc::parse-hex-hash (%aval "txid" result)))
                 (tx (%ws-mempool-tx node txid)))
            (is (eq t (%aval "complete" result)))
            (is (not (null tx)))
            (is (%ws-verify-ok-p node reloaded tx)))
          (%wc-mine node 1 (%wc-optrue-address))
          (is (= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '()))))))))

(test ws-resubmit-chunking
  "B6: the per-pass resubmission cap chunks work across passes instead of
doing unbounded validation in one housekeeping tick."
  (%with-wallet-chain-node (node "ws-chunk")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 37))
             (dest (%wc-optrue-address))
             (txid1 (bitcoin-lisp.rpc::parse-hex-hash
                     (bitcoin-lisp.rpc::rpc-sendtoaddress
                      node (list dest 1 nil nil nil nil nil nil nil 10)))))
        (%wb-evict-tx node txid1)
        (let ((txid2 (bitcoin-lisp.rpc::parse-hex-hash
                      (bitcoin-lisp.rpc::rpc-sendtoaddress
                       node (list dest 2 nil nil nil nil nil nil nil 10)))))
          (%wb-evict-tx node txid2)
          (is (null (%ws-mempool-tx node txid1)))
          (is (null (%ws-mempool-tx node txid2)))
          ;; Capped pass: one submitted, remainder flagged.
          (multiple-value-bind (submitted remaining)
              (bitcoin-lisp.rpc::wallet-resubmit-transactions
               node wallet :relay nil :force t :limit 1)
            (is (= 1 submitted))
            (is (eq t remaining)))
          ;; Follow-up pass drains the rest (the already-in-mempool tx1
          ;; counts as submitted again, exactly like Core's OK-returning
          ;; already-in-mempool branch).
          (multiple-value-bind (submitted remaining)
              (bitcoin-lisp.rpc::wallet-resubmit-transactions
               node wallet :relay nil :force t)
            (is (<= 1 submitted 2))
            (is (null remaining)))
          (is (not (null (%ws-mempool-tx node txid1))))
          (is (not (null (%ws-mempool-tx node txid2)))))))))
