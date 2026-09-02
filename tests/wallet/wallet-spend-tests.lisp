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
  (let ((coin (bl.wallet::make-wallet-coin
               :txid (%ws-txid) :index 0
               :output (bl.ser:make-tx-out
                        :value value
                        :script-pubkey (make-array 0 :element-type '(unsigned-byte 8)))
               :depth 1 :solvable t :safe t
               :input-bytes input-bytes
               :fee fee :effective-value (- value fee))))
    (setf (bl.wallet::wallet-coin-long-term-fee coin) ltf)
    coin))

(defun %ws-group (coin &key sffo)
  "One-coin OutputGroup preserving the coin's pre-set long-term fee (Core's
add_coin comment: group.Insert overwrites long_term_fee, set it after)."
  (let ((group (bl.wallet::make-out-group :subtract-fee-outputs sffo))
        (ltf (bl.wallet::wallet-coin-long-term-fee coin)))
    (bl.wallet::out-group-insert group coin 0 0)
    (setf (bl.wallet::wallet-coin-long-term-fee coin) ltf)
    (setf (bl.wallet::out-group-long-term-fee group) ltf)
    group))

(defun %ws-groups (specs &key sffo)
  "SPECS: list of (value &key fee ltf input-bytes) -> list of out-groups."
  (mapcar (lambda (spec)
            (%ws-group (apply #'%ws-coin (if (listp spec) spec (list spec)))
                       :sffo sffo))
          specs))

(defun %ws-add-to-result (result value fee ltf)
  (bl.wallet::sel-result-add-group
   result (%ws-group (%ws-coin value :fee fee :ltf ltf))))

(defun %ws-result-values (result)
  (sort (mapcar (lambda (coin)
                  (bl.ser:tx-out-value
                   (bl.wallet::wallet-coin-output coin)))
                (bl.wallet::sel-result-inputs result))
        #'<))

;;; --- CFeeRate / FormatMoney / dust arithmetic ---

(test ws-feerate-fee
  "Core CFeeRate::GetFee at d3056bc: EvaluateFeeUp — ceil(rate*size/1000),
always rounded UP (feerate.cpp:20-27, feefrac.h)."
  (is (= 0 (bl.rpc:feerate-fee 1000 0)))
  (is (= 1 (bl.rpc:feerate-fee 1000 1)))
  (is (= 1 (bl.rpc:feerate-fee 1 999)))     ; ceil(0.999)
  (is (= 1 (bl.rpc:feerate-fee 1 1000)))
  (is (= 2 (bl.rpc:feerate-fee 1 1001)))    ; ceil(1.001)
  (is (= 141 (bl.rpc:feerate-fee 1000 141)))
  (is (= 1410 (bl.rpc:feerate-fee 10000 141)))
  (is (= 423 (bl.rpc:feerate-fee 3000 141)))  ; exact
  ;; Round-up discriminator: truncation would give 422 (422.859 -> 423 up).
  (is (= 423 (bl.rpc:feerate-fee 2999 141)))
  ;; The 1300 sat/kvB case from the review: per-part round-up sums (54+40+88
  ;; = 182... under truncation the parts sum BELOW the whole ceil(183.3);
  ;; under round-up every part covers its share and the whole is 184 <= sum
  ;; of any parts covering >= its size).
  (is (= 184 (bl.rpc:feerate-fee 1300 141)))
  (is (<= (bl.rpc:feerate-fee 1300 141)
          (+ (bl.rpc:feerate-fee 1300 41)
             (bl.rpc:feerate-fee 1300 31)
             (bl.rpc:feerate-fee 1300 69))))
  (is (= 204 (bl.rpc:feerate-fee 3000 68)))   ; exact
  (is (= 0 (bl.rpc:feerate-fee 0 1000))))

(test ws-format-money
  "Core FormatMoney: trailing-zero trim keeping at least two decimals."
  (is (string= "0.00" (bl.rpc:format-money 0)))
  (is (string= "1.00" (bl.rpc:format-money 100000000)))
  (is (string= "1.50" (bl.rpc:format-money 150000000)))
  (is (string= "0.001" (bl.rpc:format-money 100000)))
  (is (string= "0.10" (bl.rpc:format-money 10000000)))
  (is (string= "0.00000123" (bl.rpc:format-money 123)))
  (is (string= "1.23456789" (bl.rpc:format-money 123456789)))
  (is (string= "-0.50" (bl.rpc:format-money -50000000))))

(test ws-dust-threshold-at-rate
  "The parameterized dust threshold agrees with the validation layer's
fixed-rate version at the 3000 sat/kvB dust relay rate."
  (let ((p2wpkh (concatenate '(vector (unsigned-byte 8))
                             #(#x00 #x14) (make-array 20 :initial-element 7)))
        (p2pkh (concatenate '(vector (unsigned-byte 8))
                            #(#x76 #xa9 #x14) (make-array 20 :initial-element 7)
                            #(#x88 #xac)))
        (op-return (coerce #(#x6a #x04 1 2 3 4) '(vector (unsigned-byte 8)))))
    (is (= (bl.val:dust-threshold p2wpkh)
           (bl.wallet::%dust-threshold-at-rate p2wpkh 3000)))
    (is (= (bl.val:dust-threshold p2pkh)
           (bl.wallet::%dust-threshold-at-rate p2pkh 3000)))
    (is (= 294 (bl.wallet::%dust-threshold-at-rate p2wpkh 3000)))
    (is (= 546 (bl.wallet::%dust-threshold-at-rate p2pkh 3000)))
    (is (= 0 (bl.wallet::%dust-threshold-at-rate op-return 3000)))))

(test ws-feerate-from-value
  "AmountFromValue(fee_rate, decimals=3): sat/vB to sat/kvB, 3 decimals max."
  (is (= 10000 (bl.wallet::%feerate-from-value 10)))
  (is (= 1100 (bl.wallet::%feerate-from-value "1.1")))
  (is (= 1001 (bl.wallet::%feerate-from-value "1.001")))
  (is (= 25000 (bl.wallet::%feerate-from-value 25)))
  (signals bl.rpc:rpc-error
    (bl.wallet::%feerate-from-value "1.0001")))

(test ws-amount-sub-satoshi-rejected
  "AmountFromValue rejects sub-satoshi precision (Core parses the decimal
text exactly and errors on >8 fraction digits); legit amounts still parse."
  (is (= 500000 (bl.rpc:amount-from-value 0.005)))
  (is (= 1 (bl.rpc:amount-from-value 1/100000000)))
  (signals bl.rpc:rpc-error
    (bl.rpc:amount-from-value 1/1000000000))        ; 0.1 sat exact
  (signals bl.rpc:rpc-error
    (bl.rpc:amount-from-value 1.23456789012d0))     ; sub-sat double
  (signals bl.rpc:rpc-error
    (bl.rpc:amount-from-value 0.000000001d0)))      ; 0.1 sat double

(test ws-positional-bool-plumbing
  "Explicit false survives JSON parsing as the +json-false+ sentinel at
top-level positional positions (distinguishable from null/omitted, Core's
isNull semantics); nested objects/arrays keep the historical present-p
folding; the %positional-bool helpers decode all three states."
  (multiple-value-bind (type method params)
      (bl.rpc::parse-json-rpc-request
       "{\"method\":\"x\",\"params\":[true,false,null,{\"a\":false,\"b\":true},[false]],\"id\":1}")
    (is (eq type :single))
    (is (string= method "x"))
    (is (eq t (first params)))
    (is (eq bl.rpc:+json-false+ (second params)))
    (is (null (third params)))
    (let ((obj (fourth params)))
      (multiple-value-bind (a present) (gethash "a" obj)
        (is (null a))
        (is (eq t present)))
      (is (eq t (gethash "b" obj))))
    (is (equal '(nil) (fifth params))))
  (is (null (bl.rpc:positional-bool
             bl.rpc:+json-false+)))
  (is (null (bl.rpc:positional-bool nil)))
  (is (eq t (bl.rpc:positional-bool t)))
  (is (eq t (bl.rpc:positional-bool-or nil t)))
  (is (null (bl.rpc:positional-bool-or
             bl.rpc:+json-false+ t)))
  (is (eq t (bl.rpc:positional-bool-or t t))))

;;; --- RNG determinism ---

(test ws-rng-determinism
  (let ((a (bl.wallet::make-wrng 42))
        (b (bl.wallet::make-wrng 42)))
    (is (equal (loop repeat 16 collect (bl.wallet::wrng-next64 a))
               (loop repeat 16 collect (bl.wallet::wrng-next64 b))))
    (is (equal (bl.wallet::wrng-shuffle
                (bl.wallet::make-wrng 7) '(1 2 3 4 5 6 7 8))
               (bl.wallet::wrng-shuffle
                (bl.wallet::make-wrng 7) '(1 2 3 4 5 6 7 8))))
    (loop repeat 200
          do (is (< (bl.wallet::wrng-randrange a 10) 10)))))

(test ws-generate-change-target
  "Core GenerateChangeTarget: fixed floor for small payments, else
change_fee + [CHANGE_LOWER, min(2*payment, CHANGE_UPPER))."
  (let ((rng (bl.wallet::make-wrng 1)))
    ;; payment <= CHANGE_LOWER/2 -> exactly change_fee + CHANGE_LOWER
    (is (= 50030 (bl.wallet::generate-change-target 25000 30 rng)))
    (loop repeat 100
          do (let ((target (bl.wallet::generate-change-target 100000 30 rng)))
               (is (<= (+ 30 50000) target))
               (is (< target (+ 30 200000)))))
    (loop repeat 100
          do (let ((target (bl.wallet::generate-change-target
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
             (let ((result (bl.wallet::make-sel-result
                            :target result-target :algo :manual)))
               (%ws-add-to-result result (* 1 +ws-coin+) coin-fee coin-ltf)
               (%ws-add-to-result result (* 2 +ws-coin+) coin-fee coin-ltf)
               (bl.wallet::sel-result-recalculate-waste
                result min-viable-change cost change-fee)
               (bl.wallet::sel-result-waste result))))
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
  (let ((max-weight bl.val:+max-standard-tx-weight+))
    ;; Exact single match.
    (multiple-value-bind (result)
        (bl.wallet::select-coins-bnb
         (%ws-groups (list (* 1 +ws-cent+) (* 2 +ws-cent+) (* 3 +ws-cent+)))
         (* 1 +ws-cent+) 0 max-weight)
      (is (not (null result)))
      (is (equal (list (* 1 +ws-cent+)) (%ws-result-values result))))
    ;; Exact multi-coin: 5 + 3 + 2 = 10.
    (multiple-value-bind (result)
        (bl.wallet::select-coins-bnb
         (%ws-groups (list (* 5 +ws-cent+) (* 3 +ws-cent+) (* 2 +ws-cent+)))
         (* 10 +ws-cent+) 0 max-weight)
      (is (not (null result)))
      (is (equal (list (* 2 +ws-cent+) (* 3 +ws-cent+) (* 5 +ws-cent+))
                 (%ws-result-values result))))
    ;; No exact combination within a zero cost-of-change window.
    (multiple-value-bind (result error)
        (bl.wallet::select-coins-bnb
         (%ws-groups (list (* 5 +ws-cent+) (* 3 +ws-cent+) (* 2 +ws-cent+)))
         (* 4 +ws-cent+) 0 max-weight)
      (is (null result))
      (is (null error)))
    ;; The cost-of-change window: value within [target, target+coc].
    (multiple-value-bind (result)
        (bl.wallet::select-coins-bnb
         (%ws-groups (list (* 10 +ws-cent+)))
         (- (* 10 +ws-cent+) 500) 1000 max-weight)
      (is (not (null result))))
    (multiple-value-bind (result)
        (bl.wallet::select-coins-bnb
         (%ws-groups (list (* 10 +ws-cent+)))
         (- (* 10 +ws-cent+) 500) 100 max-weight)
      (is (null result)))
    ;; Insufficient funds.
    (multiple-value-bind (result)
        (bl.wallet::select-coins-bnb
         (%ws-groups (list (* 1 +ws-cent+))) (* 2 +ws-cent+) 0 max-weight)
      (is (null result)))
    ;; Waste minimization: target 6 with {5,4,3,2} picks the exact 4+2.
    (multiple-value-bind (result)
        (bl.wallet::select-coins-bnb
         (%ws-groups (list (* 5 +ws-cent+) (* 4 +ws-cent+) (* 3 +ws-cent+)
                           (* 2 +ws-cent+)))
         (* 6 +ws-cent+) (* 10 +ws-cent+) max-weight)
      (is (not (null result)))
      (is (= (* 6 +ws-cent+)
             (bl.wallet::sel-result-selected-value result))))))

(test ws-bnb-max-weight
  "Core bnb_search_test's max-weight scenario at feerate 5000 / SFFO
grouping: the oversized 5-cent coin first forces the max-weight error, and
after adding a normal 5-cent coin BnB finds {8, 5, 3}."
  (flet ((spec (cents input-bytes)
           (list (* cents +ws-cent+)
                 :fee (bl.rpc:feerate-fee 5000 input-bytes)
                 :ltf 0
                 :input-bytes input-bytes)))
    (let ((max-weight bl.val:+max-standard-tx-weight+)
          (target (* 16 +ws-cent+)))
      (multiple-value-bind (result error)
          (bl.wallet::select-coins-bnb
           (%ws-groups (list (spec 10 68) (spec 9 68) (spec 8 68)
                             (spec 5 bl.val:+max-standard-tx-weight+)
                             (spec 3 68) (spec 1 68))
                       :sffo t)
           target 0 max-weight)
        (is (null result))
        (is (search "The inputs size exceeds the maximum weight" error)))
      (multiple-value-bind (result)
          (bl.wallet::select-coins-bnb
           (%ws-groups (list (spec 10 68) (spec 9 68) (spec 8 68)
                             (spec 5 bl.val:+max-standard-tx-weight+)
                             (spec 3 68) (spec 1 68) (spec 5 68))
                       :sffo t)
           target 0 max-weight)
        (is (not (null result)))
        (is (equal (list (* 3 +ws-cent+) (* 5 +ws-cent+) (* 8 +ws-cent+))
                   (%ws-result-values result)))))))

;;; --- Knapsack ---

(test ws-knapsack-basics
  (let ((rng (bl.wallet::make-wrng 99))
        (max-weight bl.val:+max-standard-tx-weight+)
        (change +ws-cent+))
    ;; Empty pool.
    (is (null (bl.wallet::knapsack-solver '() +ws-cent+ change
                                                 rng max-weight)))
    ;; Exact single match short-circuits.
    (multiple-value-bind (result)
        (bl.wallet::knapsack-solver
         (%ws-groups (list (* 1 +ws-cent+) (* 5 +ws-cent+)))
         (* 1 +ws-cent+) change rng max-weight)
      (is (equal (list (* 1 +ws-cent+)) (%ws-result-values result))))
    ;; Sum of lower coins == target -> all of them.
    (multiple-value-bind (result)
        (bl.wallet::knapsack-solver
         (%ws-groups (list (* 1 +ws-cent+) (* 2 +ws-cent+)))
         (* 3 +ws-cent+) change rng max-weight)
      (is (equal (list (* 1 +ws-cent+) (* 2 +ws-cent+))
                 (%ws-result-values result))))
    ;; Not enough smaller coins -> smallest larger coin.
    (multiple-value-bind (result)
        (bl.wallet::knapsack-solver
         (%ws-groups (list (* 5 +ws-cent+) (* 10 +ws-cent+) (* 20 +ws-cent+)))
         (* 6 +ws-cent+) change rng max-weight)
      (is (equal (list (* 10 +ws-cent+)) (%ws-result-values result))))
    ;; Nothing reaches the target at all.
    (multiple-value-bind (result)
        (bl.wallet::knapsack-solver
         (%ws-groups (list (* 1 +ws-cent+))) (* 2 +ws-cent+) change
         rng max-weight)
      (is (null result)))))

;;; --- SRD ---

(test ws-srd-basics
  (let ((max-weight bl.val:+max-standard-tx-weight+))
    ;; Sum exactly covers target + CHANGE_LOWER -> success (all coins).
    (multiple-value-bind (result)
        (bl.wallet::select-coins-srd
         (%ws-groups (make-list 10 :initial-element (* 1 +ws-cent+)))
         (- (* 10 +ws-cent+) 50000) 0
         (bl.wallet::make-wrng 3) max-weight)
      (is (not (null result)))
      (is (= (* 10 +ws-cent+)
             (bl.wallet::sel-result-selected-value result))))
    ;; One satoshi short of target + CHANGE_LOWER -> failure.
    (multiple-value-bind (result error)
        (bl.wallet::select-coins-srd
         (%ws-groups (make-list 10 :initial-element (* 1 +ws-cent+)))
         (- (* 10 +ws-cent+) 49999) 0
         (bl.wallet::make-wrng 3) max-weight)
      (is (null result))
      (is (null error)))
    ;; Deterministic under a fixed seed.
    (let ((groups (%ws-groups (list (* 1 +ws-cent+) (* 2 +ws-cent+)
                                    (* 3 +ws-cent+) (* 4 +ws-cent+)
                                    (* 5 +ws-cent+)))))
      (multiple-value-bind (a)
          (bl.wallet::select-coins-srd
           groups (* 2 +ws-cent+) 0 (bl.wallet::make-wrng 11) max-weight)
        (multiple-value-bind (b)
            (bl.wallet::select-coins-srd
             groups (* 2 +ws-cent+) 0 (bl.wallet::make-wrng 11) max-weight)
          (is (equal (%ws-result-values a) (%ws-result-values b))))))))

;;; --- Regtest end-to-end ---

(defun %ws-mempool-tx (node txid)
  (bl.rpc:with-node-lock (node)
    (let* ((mempool (bl:node-mempool node))
           (entry (and mempool (bl.mp:mempool-get mempool txid))))
      (and entry (bl.mp:mempool-entry-transaction entry)))))

(defun %ws-tx-fee (node wallet tx)
  "inputs - outputs, resolved through the wallet/UTXO/mempool coins map."
  (bl.rpc:with-node-lock (node)
    (bl.wallet::with-wallet-lock (wallet)
      (let ((coins (bl.wallet::%wallet-input-coins node wallet tx))
            (in 0))
        (bl.ser:dovector
            (input (bl.ser:transaction-inputs tx))
          (let* ((prevout (bl.ser:tx-in-previous-output input))
                 (entry (gethash (cons (bl.ser:outpoint-hash prevout)
                                       (bl.ser:outpoint-index prevout))
                                 coins)))
            (is (not (null entry)))
            (incf in (second entry))))
        (- in
           (reduce #'+ (bl.ser:transaction-outputs tx)
                   :key #'bl.ser:tx-out-value
                   :initial-value 0))))))

(defun %ws-est-vsize (node wallet tx)
  "The estimator's max signed vsize for TX (all inputs wallet-owned)."
  (bl.rpc:with-node-lock (node)
    (bl.wallet::with-wallet-lock (wallet)
      (let ((txouts
              (map 'list
                   (lambda (input)
                     (let* ((prevout (bl.ser:tx-in-previous-output input))
                            (txout (bl.wallet::%wallet-input-txout
                                    node wallet
                                    (bl.ser:outpoint-hash prevout)
                                    (bl.ser:outpoint-index prevout))))
                       (cons (bl.ser:tx-out-script-pubkey txout)
                             nil)))
                   (bl.ser:transaction-inputs tx))))
        (bl.wallet::%max-signed-tx-size wallet nil tx txouts)))))

(defun %ws-verify-ok-p (node wallet tx)
  (bl.rpc:with-node-lock (node)
    (bl.wallet::with-wallet-lock (wallet)
      (let ((coins (bl.wallet::%wallet-input-coins node wallet tx)))
        (nth-value 0 (bl.wallet::%verify-tx-scripts tx coins))))))

(defun %ws-fund-wallet (node &key (blocks 1))
  "Create wallet \"w\", mine BLOCKS coinbases to it, mature them. Returns
(values wallet address)."
  (bl.wallet::rpc-createwallet node '("w"))
  (let* ((wallet (%wc-wallet node "w"))
         (address (bl.wallet::rpc-getnewaddress node '("" "bech32"))))
    (dotimes (i blocks) (%wc-mine node 1 address))
    (%wc-mine node 101 (%wc-optrue-address))
    (values wallet address)))

(test ws-sendtoaddress-e2e
  "sendtoaddress: exact fee (= feerate x estimated vsize), internal change,
RBF sequences, anti-fee-sniping locktime, script-verifier round trip, and
balances that reconcile to the satoshi before and after confirmation."
  (with-wallet-chain-node (node "ws-send")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (is (= 50.0d0 (bl.wallet::rpc-getbalance node '())))
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 12345))
             (dest (%wc-optrue-address))
             (dest-spk (nth-value 1 (bl.crypto:decode-address
                                     dest :regtest)))
             (tip-height 102)
             (txid-hex (bl.wallet::rpc-sendtoaddress
                        node (list dest 1 nil nil nil nil nil nil nil 10)))
             (txid (bl.rpc:parse-hex-hash txid-hex))
             (tx (%ws-mempool-tx node txid)))
        (is (not (null tx)))
        (let* ((outputs (bl.ser:transaction-outputs tx))
               (fee (%ws-tx-fee node wallet tx))
               (est-vsize (%ws-est-vsize node wallet tx)))
          (is (= 2 (length outputs)))
          ;; Exact fee: feerate 10 sat/vB x estimated max signed vsize.
          (is (= fee (bl.rpc:feerate-fee 10000 est-vsize)))
          ;; Actual signed weight never exceeds the estimate.
          (is (<= (bl.ser:transaction-weight tx)
                  (nth-value 1 (%ws-est-vsize node wallet tx))))
          ;; Recipient output exact; the other output is OUR change.
          (let ((pay (find dest-spk (coerce outputs 'list)
                           :key #'bl.ser:tx-out-script-pubkey
                           :test #'equalp)))
            (is (not (null pay)))
            (is (= 100000000 (bl.ser:tx-out-value pay)))
            (let ((change (find pay (coerce outputs 'list) :test-not #'eq)))
              (is (bl.wallet::wallet-is-mine
                   wallet (bl.ser:tx-out-script-pubkey change)))
              ;; Change address is an internal-chain (ischange) address.
              (let* ((change-addr (bl.rpc:script->address
                                   (bl.ser:tx-out-script-pubkey change)
                                   :regtest))
                     (info (bl.wallet::rpc-getaddressinfo
                            node (list change-addr))))
                (is (eq t (%aval "ischange" info))))))
          ;; RBF default sequences.
          (bl.ser:dovector
              (input (bl.ser:transaction-inputs tx))
            (is (= #xFFFFFFFD (bl.ser:tx-in-sequence input))))
          ;; Anti-fee-sniping: locktime at (or up to 99 below) the tip.
          (let ((locktime (bl.ser:transaction-lock-time tx)))
            (is (<= (- tip-height 99) locktime tip-height)))
          ;; The committed tx verifies against the exact spent scripts.
          (is (%ws-verify-ok-p node wallet tx))
          ;; Balance before confirmation: change is trusted (own zero-conf).
          (is (= (/ (- 5000000000 100000000 fee) 100000000.0d0)
                 (bl.wallet::rpc-getbalance node '())))
          ;; Confirm; balances identical, gettransaction agrees on the fee.
          (%wc-mine node 1 (%wc-optrue-address))
          (is (= (/ (- 5000000000 100000000 fee) 100000000.0d0)
                 (bl.wallet::rpc-getbalance node '())))
          (let ((gettx (%wc-gettx node txid)))
            (is (= 1 (%aval "confirmations" gettx)))
            (is (= (/ (- fee) 100000000.0d0) (%aval "fee" gettx)))))))))

(test ws-sffo-single-and-multi
  "Subtract-fee-from-outputs: single recipient pays exactly the fee;
multi-recipient splits it with the first (in built-tx order) paying the
remainder."
  (with-wallet-chain-node (node "ws-sffo")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 777))
             (dest (%wc-optrue-address))
             (dest-spk (nth-value 1 (bl.crypto:decode-address
                                     dest :regtest))))
        ;; Single-recipient SFFO.
        (let* ((txid (bl.rpc:parse-hex-hash
                      (bl.wallet::rpc-sendtoaddress
                       node (list dest 1 nil nil t nil nil nil nil 10))))
               (tx (%ws-mempool-tx node txid))
               (fee (%ws-tx-fee node wallet tx))
               (pay (find dest-spk
                          (coerce (bl.ser:transaction-outputs tx)
                                  'list)
                          :key #'bl.ser:tx-out-script-pubkey
                          :test #'equalp)))
          (is (not (null tx)))
          (is (= (- 100000000 fee)
                 (bl.ser:tx-out-value pay)))
          (is (= fee (bl.rpc:feerate-fee
                      10000 (%ws-est-vsize node wallet tx)))))
        ;; Multi-recipient SFFO through sendmany: fee split over both, one
        ;; recipient pays floor(fee/2)+rem, the other floor(fee/2).
        (let* ((redeem-2 (coerce #(#x51 #x51) '(vector (unsigned-byte 8)))) ; OP_TRUE OP_TRUE
               (dest2 (bl.crypto:encode-p2sh-address
                       (bl.crypto:hash160 redeem-2) :regtest))
               (dest2-spk (nth-value 1 (bl.crypto:decode-address
                                        dest2 :regtest)))
               (txid (bl.rpc:parse-hex-hash
                      (bl.wallet::rpc-sendmany
                       node (list "" (list (cons dest 2) (cons dest2 1))
                                  nil nil (list dest dest2) nil nil nil 10))))
               (tx (%ws-mempool-tx node txid))
               (fee (%ws-tx-fee node wallet tx))
               (outputs (coerce (bl.ser:transaction-outputs tx)
                                'list))
               (pay1 (find dest-spk outputs
                           :key #'bl.ser:tx-out-script-pubkey
                           :test #'equalp))
               (pay2 (find dest2-spk outputs
                           :key #'bl.ser:tx-out-script-pubkey
                           :test #'equalp))
               (share (truncate fee 2))
               (remainder (rem fee 2)))
          (is (not (null tx)))
          (is (not (null pay1)))
          (is (not (null pay2)))
          (let ((v1 (bl.ser:tx-out-value pay1))
                (v2 (bl.ser:tx-out-value pay2)))
            ;; Sum reconciles exactly; the remainder lands on exactly one.
            (is (= (+ v1 v2) (- 300000000 fee)))
            (is (or (and (= v1 (- 200000000 share remainder))
                         (= v2 (- 100000000 share)))
                    (and (= v1 (- 200000000 share))
                         (= v2 (- 100000000 share remainder)))))))))))

(test ws-dust-change-to-fee
  "A remainder below the minimum viable change is discarded to fees: the
tx gets no change output and overpays exactly the remainder."
  (with-wallet-chain-node (node "ws-dust")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 5))
             (dest (%wc-optrue-address))
             (amount-sat (- 5000000000 900))
             (txid (bl.rpc:parse-hex-hash
                    (bl.wallet::rpc-sendtoaddress
                     node (list dest (format nil "~D.~8,'0D"
                                             (truncate amount-sat 100000000)
                                             (mod amount-sat 100000000))
                                nil nil nil nil nil nil nil 1))))
             (tx (%ws-mempool-tx node txid)))
        (is (not (null tx)))
        (is (= 1 (length (bl.ser:transaction-outputs tx))))
        (is (= 900 (%ws-tx-fee node wallet tx)))
        (is (%ws-verify-ok-p node wallet tx))))))

(test ws-sendall-sweep
  "sendall sweeps every coin: fee = feerate x estimated size, single
output of total - fee, wallet empty afterwards."
  (with-wallet-chain-node (node "ws-sendall")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 21))
             (dest (%wc-optrue-address))
             (result (bl.wallet::rpc-sendall
                      node (list (list dest) nil nil 10)))
             (txid (bl.rpc:parse-hex-hash (%aval "txid" result)))
             (tx (%ws-mempool-tx node txid)))
        (is (eq t (%aval "complete" result)))
        (is (not (null tx)))
        (is (= 2 (length (bl.ser:transaction-inputs tx))))
        (is (= 1 (length (bl.ser:transaction-outputs tx))))
        (let ((fee (%ws-tx-fee node wallet tx))
              (est (%ws-est-vsize node wallet tx)))
          (is (= fee (bl.rpc:feerate-fee 10000 est)))
          (is (= (- 10000000000 fee)
                 (bl.ser:tx-out-value
                  (aref (bl.ser:transaction-outputs tx) 0)))))
        (is (%ws-verify-ok-p node wallet tx))
        (%wc-mine node 1 (%wc-optrue-address))
        (is (= 0.0d0 (bl.wallet::rpc-getbalance node '())))))))

(test ws-fundrawtransaction-sign-broadcast
  "fundrawtransaction on an externally-built raw tx adds change at the
requested feerate; signrawtransactionwithwallet completes it;
sendrawtransaction accepts it. Preset locktime/sequence survive."
  (with-wallet-chain-node (node "ws-fund")
    (multiple-value-bind (wallet address) (%ws-fund-wallet node)
      (declare (ignore address))
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 31))
             (coins (bl.wallet::with-wallet-lock (wallet)
                      (bl.wallet::wallet-available-coins wallet)))
             (coin (first coins))
             (raw (bl.ser:make-transaction
                   :version 2
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output (bl.ser:make-outpoint
                                                      :hash (bl.wallet::wallet-coin-txid coin)
                                                      :index (bl.wallet::wallet-coin-index coin))
                                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                    :sequence #xFFFFFFFE))
                   :outputs (vector (bl.ser:make-tx-out
                                     :value 100000000
                                     :script-pubkey (p2sh-optrue-script-pubkey)))
                   :lock-time 0))
             (funded (bl.wallet::rpc-fundrawtransaction
                      node (list (bl.crypto:bytes-to-hex
                                  (bl.ser:transaction-wire-bytes raw))
                                 '(("fee_rate" . 10)))))
             (fee-btc (%aval "fee" funded))
             (changepos (%aval "changepos" funded)))
        (is (member changepos '(0 1)))
        (is (> fee-btc 0))
        (let* ((funded-tx (bl.ser:parse-tx-payload
                           (bl.crypto:hex-to-bytes (%aval "hex" funded)))))
          ;; Preset sequence and locktime preserved; no anti-fee-sniping.
          (is (zerop (bl.ser:transaction-lock-time funded-tx)))
          (is (= #xFFFFFFFE
                 (bl.ser:tx-in-sequence
                  (aref (bl.ser:transaction-inputs funded-tx) 0))))
          ;; Exact fee at 10 sat/vB over the estimator's size.
          (is (= (round (* fee-btc 100000000))
                 (bl.rpc:feerate-fee
                  10000 (%ws-est-vsize node wallet funded-tx)))))
        (let ((signed (bl.wallet::rpc-signrawtransactionwithwallet
                       node (list (%aval "hex" funded)))))
          (is (eq t (%aval "complete" signed)))
          (let ((txid-hex (bl.rpc::rpc-sendrawtransaction
                           node (list (%aval "hex" signed)))))
            (is (stringp txid-hex))
            (is (not (null (%ws-mempool-tx
                            node (bl.rpc:parse-hex-hash txid-hex)))))))))))

(test ws-signraw-watch-only-partial
  "signrawtransactionwithwallet on a watch-only wallet returns
complete:false with Core's per-input errors array."
  (with-wallet-chain-node (node "ws-watch")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (declare (ignore wallet))
      ;; Watch-only wallet from an xpub descriptor.
      (bl.wallet::rpc-createwallet node '("wo" t t))
      (let* ((seed (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 7))
             (xprv (bl.crypto:bip32-master-key seed :network :testnet3))
             (xpub (bl.crypto:bip32-serialize
                    (bl.crypto:bip32-neuter xprv)))
             (desc (bl.rpc:descriptor-add-checksum
                    (format nil "wpkh(~A/0/*)" xpub)))
             (request (make-hash-table :test 'equal)))
        (setf (gethash "desc" request) desc
              (gethash "timestamp" request) "now"
              (gethash "active" request) t)
        (let ((bl.wallet::*rpc-wallet-name* "wo"))
          (let ((results (bl.wallet::rpc-importdescriptors
                          node (list (list request)))))
            (is (eq t (%aval "success" (first results))))))
        (let* ((wo-address (let ((bl.wallet::*rpc-wallet-name* "wo"))
                             (bl.wallet::rpc-getnewaddress
                              node '("" "bech32"))))
               (bl.wallet::*wallet-rng* (bl.wallet::make-wrng 8))
               (fund-txid (bl.rpc:parse-hex-hash
                           (let ((bl.wallet::*rpc-wallet-name* "w"))
                             (bl.wallet::rpc-sendtoaddress
                              node (list wo-address 1 nil nil nil nil nil nil
                                         nil 10))))))
          (%wc-mine node 1 (%wc-optrue-address))
          ;; Find the funded outpoint.
          (let* ((fund-tx (let ((bl.wallet::*rpc-wallet-name* "w"))
                            (bl.ser:parse-tx-payload
                             (bl.crypto:hex-to-bytes
                              (%aval "hex" (bl.wallet::rpc-gettransaction
                                            node (list (bl.rpc:hash-to-hex
                                                        fund-txid))))))))
                 (wo-spk (nth-value 1 (bl.crypto:decode-address
                                       wo-address :regtest)))
                 (vout (position wo-spk
                                 (coerce (bl.ser:transaction-outputs
                                          fund-tx)
                                         'list)
                                 :key #'bl.ser:tx-out-script-pubkey
                                 :test #'equalp))
                 (spend (bl.ser:make-transaction
                         :version 2
                         :inputs (vector (bl.ser:make-tx-in
                                          :previous-output (bl.ser:make-outpoint
                                                            :hash fund-txid :index vout)
                                          :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                          :sequence #xFFFFFFFD))
                         :outputs (vector (bl.ser:make-tx-out
                                           :value 90000000
                                           :script-pubkey (p2sh-optrue-script-pubkey)))
                         :lock-time 0))
                 (result (let ((bl.wallet::*rpc-wallet-name* "wo"))
                           (bl.wallet::rpc-signrawtransactionwithwallet
                            node (list (bl.crypto:bytes-to-hex
                                        (bl.ser:transaction-wire-bytes
                                         spend)))))))
            (is (not (null vout)))
            (is (eq bl.rpc:+json-false+ (%aval "complete" result)))
            (let ((errors (%aval "errors" result)))
              (is (= 1 (length errors)))
              (let ((entry (first errors)))
                (is (string= (bl.rpc:hash-to-hex fund-txid)
                             (%aval "txid" entry)))
                (is (= vout (%aval "vout" entry)))
                (is (stringp (%aval "error" entry)))
                (is (search "no key" (%aval "error" entry)))
                (is (= #xFFFFFFFD (%aval "sequence" entry)))))))))))

(test ws-maxtxfee-and-weight-caps
  "The -maxtxfee rail refuses to build over-fee transactions; max_tx_weight
bounds are enforced with Core's messages."
  (with-wallet-chain-node (node "ws-caps")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (declare (ignore wallet))
      (let ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 61))
            (dest (%wc-optrue-address)))
        ;; maxtxfee: a 10 sat/vB spend costs ~1400+ sats; cap at 100.
        (let ((bl:*wallet-max-tx-fee* 100))
          (signals-rpc-error (:code -6 :message "Fee exceeds maximum configured by user")
            (bl.wallet::rpc-sendtoaddress
             node (list dest 1 nil nil nil nil nil nil nil 10))))
        ;; Weight caps via send's max_tx_weight.
        (signals-rpc-error (:message "Maximum transaction weight must be between")
          (bl.wallet::rpc-send
           node (list (list (cons dest 1)) nil nil 10
                      '(("max_tx_weight" . 100)))))
        (handler-case
            (progn (bl.wallet::rpc-send
                    node (list (list (cons dest 1)) nil nil 10
                               '(("max_tx_weight" . 300))))
                   (fail "max_tx_weight cap not enforced"))
          (bl.rpc:rpc-error (e)
            ;; The 300-weight budget dies in selection: no input fits.
            (is (search "maximum weight"
                        (bl.rpc:rpc-error-message e)
                        :test #'char-equal))))))))

(test ws-fee-estimation-paths
  "Fallback fee drives fee estimation when the estimator has no data;
disabled fallback errors with Core's message; explicit feerates report
PayTxFee."
  (with-wallet-chain-node (node "ws-fees")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 77))
            (dest (%wc-optrue-address)))
        ;; Fallback disabled (default): estimation failure.
        (signals-rpc-error (:code -6 :message "Fallbackfee is disabled")
          (bl.wallet::rpc-sendtoaddress
           node (list dest 1)))
        ;; Fallback enabled: 20 sat/vB fallback, verbose reports the reason.
        (let* ((bl:*wallet-fallback-fee* 20000)
               (result (bl.wallet::rpc-sendtoaddress
                        node (list dest 1 nil nil nil nil nil nil nil nil t)))
               (txid (bl.rpc:parse-hex-hash (%aval "txid" result)))
               (tx (%ws-mempool-tx node txid)))
          (is (string= "Fallback fee" (%aval "fee_reason" result)))
          (is (not (null tx)))
          (is (= (%ws-tx-fee node wallet tx)
                 (bl.rpc:feerate-fee
                  20000 (%ws-est-vsize node wallet tx)))))
        ;; Explicit fee rate reports PayTxFee.
        (let ((result (bl.wallet::rpc-sendtoaddress
                       node (list dest 1 nil nil nil nil nil nil nil 10 t))))
          (is (string= "PayTxFee set" (%aval "fee_reason" result))))))))

(test ws-anti-fee-sniping-direct
  "DiscourageFeeSniping: locktime = tip height, or backed off by up to 99
on the 1-in-10 branch; a FINAL sequence is an internal-bug error."
  (with-wallet-chain-node (node "ws-snipe")
    (%ws-fund-wallet node)
    (let* ((tip-hash (bl.store:best-block-hash
                      (bl:node-chain-state node)))
           (tip-height 102)
           (make-tx (lambda (sequence)
                      (bl.ser:make-transaction
                       :version 2
                       :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash (%ws-txid) :index 0)
                                        :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                        :sequence sequence))
                       :outputs (vector (bl.ser:make-tx-out
                                         :value 1000
                                         :script-pubkey (p2sh-optrue-script-pubkey)))
                       :lock-time 0)))
           ;; Find seeds whose FIRST randrange(10) draw is nonzero / zero.
           (seed-tip (loop for seed from 1
                           when (plusp (bl.wallet::wrng-randrange
                                        (bl.wallet::make-wrng seed) 10))
                             return seed))
           (seed-back (loop for seed from 1
                            when (zerop (bl.wallet::wrng-randrange
                                         (bl.wallet::make-wrng seed) 10))
                              return seed)))
      (bl.rpc:with-node-lock (node)
        ;; Non-backdated branch: locktime = tip height.
        (let ((tx (funcall make-tx #xFFFFFFFD)))
          (bl.wallet::discourage-fee-sniping
           tx (bl.wallet::make-wrng seed-tip) node tip-hash tip-height)
          (is (= tip-height
                 (bl.ser:transaction-lock-time tx))))
        ;; Backdated branch: exactly height - randrange(100), replayed.
        (let ((tx (funcall make-tx #xFFFFFFFE))
              (replay (bl.wallet::make-wrng seed-back)))
          (bl.wallet::wrng-randrange replay 10)
          (let ((expected (max 0 (- tip-height
                                    (bl.wallet::wrng-randrange replay 100)))))
            (bl.wallet::discourage-fee-sniping
             tx (bl.wallet::make-wrng seed-back) node tip-hash tip-height)
            (is (= expected
                   (bl.ser:transaction-lock-time tx)))))
        ;; FINAL sequence violates the anti-fee-sniping contract.
        (signals bl.rpc:rpc-error
          (bl.wallet::discourage-fee-sniping
           (funcall make-tx #xFFFFFFFF)
           (bl.wallet::make-wrng seed-tip) node tip-hash tip-height))))))

(test ws-nonfinal-sequence-when-rbf-off
  "With BIP125 signaling off, inputs carry MAX_SEQUENCE_NONFINAL."
  (with-wallet-chain-node (node "ws-seq")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 4)))
        (bl.rpc:with-node-lock (node)
          (bl.wallet::with-wallet-lock (wallet)
            (multiple-value-bind (tx)
                (bl.wallet::%create-transaction
                 node wallet
                 (list (bl.rpc:make-recipient
                        :address (%wc-optrue-address)
                        :script (p2sh-optrue-script-pubkey)
                        :amount 100000000))
                 nil
                 (bl.wallet::make-wcc :signal-bip125-rbf nil
                                             :feerate 10000)
                 t)
              (is (not (null tx)))
              (bl.ser:dovector
                  (input (bl.ser:transaction-inputs tx))
                (is (= #xFFFFFFFE
                       (bl.ser:tx-in-sequence input)))))))))))

(test ws-rebroadcast-machinery
  "ResubmitWalletTransactions puts an evicted wallet tx back into the
mempool; the resend scheduler windows land in [12h, 36h)."
  (with-wallet-chain-node (node "ws-resend")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 51))
             (dest (%wc-optrue-address))
             (txid (bl.rpc:parse-hex-hash
                    (bl.wallet::rpc-sendtoaddress
                     node (list dest 1 nil nil nil nil nil nil nil 10)))))
        (is (not (null (%ws-mempool-tx node txid))))
        (%wb-evict-tx node txid)
        (is (null (%ws-mempool-tx node txid)))
        ;; Non-forced resubmit skips fresh txs (received < 5 min after the
        ;; last block).
        (is (= 0 (bl.wallet::wallet-resubmit-transactions
                  node wallet :relay nil)))
        (is (null (%ws-mempool-tx node txid)))
        ;; Forced resubmit (the wallet-load path) restores it.
        (is (= 1 (bl.wallet::wallet-resubmit-transactions
                  node wallet :relay nil :force t)))
        (is (not (null (%ws-mempool-tx node txid))))
        (bl.wallet::with-wallet-lock (wallet)
          (is (eq :in-mempool
                  (bl.wallet::wallet-tx-state
                   (bl.wallet::wallet-get-wallet-tx wallet txid)))))
        ;; Resend scheduling window.
        (let* ((now (bl.ser:get-unix-time))
               (next (bl.wallet::%wallet-default-next-resend
                      (bl.wallet::make-wrng 9))))
          (is (<= (+ now (* 12 3600)) next))
          (is (< next (+ now (* 36 3600) 2))))))))

(test ws-send-rpc-e2e
  "send: commits and broadcasts by default; add_to_wallet=false returns
hex+psbt without committing."
  (with-wallet-chain-node (node "ws-sendrpc")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 43))
             (dest (%wc-optrue-address))
             (result (bl.wallet::rpc-send
                      node (list (list (cons dest 1)) nil nil 10 nil))))
        (is (eq t (%aval "complete" result)))
        (let ((txid (bl.rpc:parse-hex-hash (%aval "txid" result))))
          (is (not (null (%ws-mempool-tx node txid))))
          (is (null (%aval "hex" result))))
        ;; add_to_wallet false: hex + psbt returned, nothing committed.
        (let* ((result2 (bl.wallet::rpc-send
                         node (list (list (cons dest 1)) nil nil 10
                                    '(("add_to_wallet" . nil)))))
               (txid2 (bl.rpc:parse-hex-hash (%aval "txid" result2))))
          (is (eq t (%aval "complete" result2)))
          (is (stringp (%aval "hex" result2)))
          (is (stringp (%aval "psbt" result2)))
          (is (null (%ws-mempool-tx node txid2)))
          (bl.wallet::with-wallet-lock (wallet)
            (is (null (bl.wallet::wallet-get-wallet-tx wallet txid2))))
          ;; The returned PSBT parses and wraps the same unsigned skeleton.
          (let ((psbt (bl.ser:decode-psbt
                       (%aval "psbt" result2))))
            (is (= 1 (length (bl.ser:transaction-inputs
                              (bl.ser:psbt-tx psbt)))))))))))

;;; --- Adversarial-review regression tests (PR #293 review round) ---

(test ws-sffo-negative-data-output-rejected
  "B2: SFFO driving an OP_RETURN output negative is DUST (threshold 0) and
must error with Core's too-small-to-pay-the-fee message instead of
committing a mempool-invalid transaction as success."
  (with-wallet-chain-node (node "ws-sffo-neg")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (let ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 13))
            (dest (%wc-optrue-address))
            (mempool-before
              (bl.rpc:with-node-lock (node)
                (bl.mp:mempool-count
                 (bl:node-mempool node)))))
        (signals-rpc-error (:message "too small to pay the fee")
          (bl.wallet::rpc-send
           node (list (list (list (cons dest 1/1000))
                            (list (cons "data" "aa")))
                      nil nil 10
                      '(("subtract_fee_from_outputs" . (1))))))
        ;; Nothing committed, nothing in the mempool, no coins spent.
        (is (= mempool-before
               (bl.rpc:with-node-lock (node)
                 (bl.mp:mempool-count
                  (bl:node-mempool node)))))
        (bl.wallet::with-wallet-lock (wallet)
          (is (= 1 (hash-table-count
                    (bl.wallet::wallet-map-wallet wallet)))))))))

(test ws-sendall-sweeps-reused-coins
  "B3: sendall on an avoid_reuse wallet still sweeps coins on previously
used addresses (Core AvailableCoins allow_used with sendall's default
coin control; excluding them would strand funds)."
  (with-wallet-chain-node (node "ws-reuse")
    ;; avoid_reuse wallet.
    (bl.wallet::rpc-createwallet node '("w" nil nil nil t))
    (let* ((wallet (%wc-wallet node "w"))
           (addr-a (bl.wallet::rpc-getnewaddress node '("" "bech32")))
           (addr-b (bl.wallet::rpc-getnewaddress node '("" "bech32")))
           (bl.wallet::*wallet-rng* (bl.wallet::make-wrng 17)))
      (is (bl.wallet::wallet-flag-set-p
           wallet bl.wallet::+wallet-flag-avoid-reuse+))
      ;; Fund A, spend from A (marks A previously-spent), then fund A again
      ;; (reused coin) and B (clean coin).
      (%wc-mine node 1 addr-a)
      (%wc-mine node 101 (%wc-optrue-address))
      (let ((sweep1 (bl.wallet::rpc-sendall
                     node (list (list (%wc-optrue-address)) nil nil 2))))
        (is (eq t (%aval "complete" sweep1))))
      (%wc-mine node 1 (%wc-optrue-address))
      (is (bl.wallet::wallet-address-previously-spent-p wallet addr-a))
      (%wc-mine node 1 addr-a)
      (%wc-mine node 1 addr-b)
      (%wc-mine node 101 (%wc-optrue-address))
      ;; The default balance hides the reused coin ...
      (is (= 50.0d0 (bl.wallet::rpc-getbalance node '())))
      ;; ... but sendall sweeps BOTH coins.
      (let* ((result (bl.wallet::rpc-sendall
                      node (list (list (%wc-optrue-address)) nil nil 2)))
             (txid (bl.rpc:parse-hex-hash (%aval "txid" result)))
             (tx (%ws-mempool-tx node txid)))
        (is (eq t (%aval "complete" result)))
        (is (not (null tx)))
        (is (= 2 (length (bl.ser:transaction-inputs tx)))))
      (%wc-mine node 1 (%wc-optrue-address))
      (is (= 0.0d0 (bl.wallet::rpc-getbalance node '())))
      ;; getbalances "used" is empty too: everything left the wallet.
      (let ((balances (%wb-balances node)))
        (is (= 0.0d0 (%wb-aval "trusted" balances)))
        (is (= 0.0d0 (%wb-aval "used" balances)))))))

(test ws-explicit-false-positional-booleans
  "B4: explicit false on positional funds-policy booleans is honored.
replaceable=false turns RBF signaling off (nonfinal sequences); a
null-padded avoid_reuse keeps the wallet default while explicit true on a
wallet without the flag errors."
  (with-wallet-chain-node (node "ws-bools")
    (multiple-value-bind (wallet) (%ws-fund-wallet node)
      (declare (ignore wallet))
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 23))
             (dest (%wc-optrue-address))
             (txid (bl.rpc:parse-hex-hash
                    (bl.wallet::rpc-sendtoaddress
                     node (list dest 1 nil nil nil
                                bl.rpc:+json-false+
                                nil nil nil 10))))
             (tx (%ws-mempool-tx node txid)))
        (is (not (null tx)))
        (bl.ser:dovector
            (input (bl.ser:transaction-inputs tx))
          (is (= #xFFFFFFFE
                 (bl.ser:tx-in-sequence input)))))
      ;; avoid_reuse positional: null-padded (the normal way to reach
      ;; fee_rate at position 9) = wallet default -> fine on a wallet
      ;; without the flag; explicit true errors (Core GetAvoidReuseFlag).
      (is (numberp (bl.wallet::rpc-getbalance
                    node (list "*" 0 nil nil))))
      (signals-rpc-error (:code -4)
        (bl.wallet::rpc-getbalance node (list "*" 0 nil t)))
      ;; createwallet: explicit descriptors=false is rejected; a null-padded
      ;; descriptors argument keeps the default (true) and succeeds.
      (signals-rpc-error (:message "no longer possible to create a legacy wallet")
        (bl.wallet::rpc-createwallet
         node (list "wleg" nil nil nil nil
                    bl.rpc:+json-false+)))
      (is (equal "wnull"
                 (%aval "name" (bl.wallet::rpc-createwallet
                                node (list "wnull" nil nil nil nil nil))))))))

(test ws-taproot-spend-and-oddy-reload
  "B5: taproot end-to-end — the default wallet's tr() descriptor signs a
keypath spend, and an imported tr(WIF) with an ODD-Y internal key still
signs after a full unload/reload cycle (the persisted public descriptor
stores only the 32-byte x coordinate)."
  (with-wallet-chain-node (node "ws-tr")
    (bl.wallet::rpc-createwallet node '("w"))
    (let* ((wallet (%wc-wallet node "w"))
           (addr-tr (bl.wallet::rpc-getnewaddress node '("" "bech32m")))
           (bl.wallet::*wallet-rng* (bl.wallet::make-wrng 29))
           (dest (%wc-optrue-address)))
      ;; Fund the default 86h tr() descriptor and spend from it (BIP86
      ;; keypath through the wallet signer + script verifier).
      (%wc-mine node 1 addr-tr)
      (%wc-mine node 101 (%wc-optrue-address))
      (let* ((txid (bl.rpc:parse-hex-hash
                    (bl.wallet::rpc-sendtoaddress
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
                         when (= 3 (aref (bl.crypto:derive-public-key
                                          candidate :compressed t)
                                         0))
                           return candidate))
             (wif (bl.crypto:private-key-to-wif
                   priv :network :testnet3 :compressed t))
             (desc (bl.rpc:descriptor-add-checksum
                    (format nil "tr(~A)" wif)))
             (qx (bl.interop:compute-tweaked-pubkey
                  (bl.crypto:derive-xonly-pubkey priv)))
             (tr-address (bl.crypto:segwit-address-encode
                          "bcrt" 1 qx))
             (request (make-hash-table :test 'equal)))
        (setf (gethash "desc" request) desc
              (gethash "timestamp" request) "now")
        (let ((results (bl.wallet::rpc-importdescriptors
                        node (list (list request)))))
          (is (eq t (%aval "success" (first results)))))
        ;; Fund the imported odd-Y taproot address from the same wallet.
        (bl.wallet::rpc-sendtoaddress
         node (list tr-address 1 nil nil nil nil nil nil nil 10))
        (%wc-mine node 1 (%wc-optrue-address))
        ;; Crash-close + reload: the imported descriptor comes back from its
        ;; persisted PUBLIC form (bare x-only hex).
        (bl.wallet::rpc-unloadwallet node (list "w"))
        (bl.wallet::rpc-loadwallet node (list "w"))
        (let ((reloaded (%wc-wallet node "w")))
          (is (not (null reloaded)))
          ;; Sweep everything — including the odd-Y tr(WIF) coin, which is
          ;; only signable when x-only keys are matched by X coordinate.
          (let* ((result (bl.wallet::rpc-sendall
                          node (list (list dest) nil nil 10)))
                 (txid (bl.rpc:parse-hex-hash (%aval "txid" result)))
                 (tx (%ws-mempool-tx node txid)))
            (is (eq t (%aval "complete" result)))
            (is (not (null tx)))
            (is (%ws-verify-ok-p node reloaded tx)))
          (%wc-mine node 1 (%wc-optrue-address))
          (is (= 0.0d0 (bl.wallet::rpc-getbalance node '()))))))))

(test ws-resubmit-chunking
  "B6: the per-pass resubmission cap chunks work across passes instead of
doing unbounded validation in one housekeeping tick."
  (with-wallet-chain-node (node "ws-chunk")
    (multiple-value-bind (wallet) (%ws-fund-wallet node :blocks 2)
      (let* ((bl.wallet::*wallet-rng* (bl.wallet::make-wrng 37))
             (dest (%wc-optrue-address))
             (txid1 (bl.rpc:parse-hex-hash
                     (bl.wallet::rpc-sendtoaddress
                      node (list dest 1 nil nil nil nil nil nil nil 10)))))
        (%wb-evict-tx node txid1)
        (let ((txid2 (bl.rpc:parse-hex-hash
                      (bl.wallet::rpc-sendtoaddress
                       node (list dest 2 nil nil nil nil nil nil nil 10)))))
          (%wb-evict-tx node txid2)
          (is (null (%ws-mempool-tx node txid1)))
          (is (null (%ws-mempool-tx node txid2)))
          ;; Capped pass: one submitted, remainder flagged.
          (multiple-value-bind (submitted remaining)
              (bl.wallet::wallet-resubmit-transactions
               node wallet :relay nil :force t :limit 1)
            (is (= 1 submitted))
            (is (eq t remaining)))
          ;; Follow-up pass drains the rest (the already-in-mempool tx1
          ;; counts as submitted again, exactly like Core's OK-returning
          ;; already-in-mempool branch).
          (multiple-value-bind (submitted remaining)
              (bl.wallet::wallet-resubmit-transactions
               node wallet :relay nil :force t)
            (is (<= 1 submitted 2))
            (is (null remaining)))
          (is (not (null (%ws-mempool-tx node txid1))))
          (is (not (null (%ws-mempool-tx node txid2)))))))))
