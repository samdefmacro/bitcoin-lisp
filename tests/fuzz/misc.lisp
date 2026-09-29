(in-package #:bitcoin-lisp.tests)

;;;; Core's remaining single-subsystem targets at the pin: fuzz/parse_numbers.cpp,
;;;; hex.cpp, pow.cpp (pow_transition, and the compact-target half of pow),
;;;; merkleblock.cpp, blockfilter.cpp and minisketch.cpp.

(def-suite :fuzz-misc-tests :in :bitcoin-lisp-tests
  :description "Core fuzz parse_numbers / hex / pow / merkleblock / blockfilter / minisketch targets")

(in-suite :fuzz-misc-tests)

;;; --- parse_numbers.cpp ----------------------------------------------------------------

(defparameter +core-space-chars+
  (list #\Space #\Page #\Newline #\Return #\Tab (code-char 11))
  "Core IsSpace / TrimString's default pattern: \" \\f\\n\\r\\t\\v\".")

(defun core-locale-independent-atoi (string)
  "Core LocaleIndependentAtoi<int64_t> (util/strencodings.h:117-143), as a
reference: trim, one leading `+' (but `+-' is 0), then std::from_chars --
an optional `-' and the longest run of digits, 0 when there are none --
saturating at the int64 bounds."
  (let* ((s (string-trim +core-space-chars+ string))
         (start 0))
    (when (and (plusp (length s)) (char= (char s 0) #\+))
      (when (and (>= (length s) 2) (char= (char s 1) #\-))
        (return-from core-locale-independent-atoi 0))
      (setf start 1))
    (let* ((neg (and (< start (length s)) (char= (char s start) #\-)))
           (digits-start (if neg (1+ start) start))
           (end (or (position-if-not (lambda (c) (char<= #\0 c #\9)) s :start digits-start)
                    (length s))))
      (if (= end digits-start)
          0
          (let ((v (* (if neg -1 1) (parse-integer s :start digits-start :end end))))
            (max (- (ash 1 63)) (min (1- (ash 1 63)) v)))))))

(defun core-parse-money (string)
  "Core ParseMoney (util/moneystr.cpp:45-94), as a reference."
  (when (find (code-char 0) string) (return-from core-parse-money nil))
  (let ((s (string-trim +core-space-chars+ string))
        (whole '()) (units 0) (p 0))
    (when (zerop (length s)) (return-from core-parse-money nil))
    (loop while (< p (length s))
          do (let ((c (char s p)))
               (cond ((char= c #\.)
                      (incf p)
                      (let ((mult 10000000))
                        (loop while (and (< p (length s)) (char<= #\0 (char s p) #\9) (plusp mult))
                              do (incf units (* mult (- (char-code (char s p)) 48)))
                                 (incf p)
                                 (setf mult (floor mult 10))))
                      (return))
                     ((not (char<= #\0 c #\9)) (return-from core-parse-money nil))
                     (t (push c whole) (incf p)))))
    (when (< p (length s)) (return-from core-parse-money nil))
    (when (> (length whole) 10) (return-from core-parse-money nil))
    (let ((value (+ (* (core-locale-independent-atoi (coerce (reverse whole) 'string)) 100000000)
                    units)))
      (when (<= 0 value bl.val:+max-money+) value))))

(define-fuzz-target parse-numbers
    (buffer :core "parse_numbers.cpp:13-60" :iterations 20000 :max-len 40
            :corpus (lambda (fdp)
                      (%octets-of-string
                       (format nil "~A~A~A~A~A~A"
                               (pick-value-in-array fdp (list "" " " "+" "-" "+-" "++" "--" (string (code-char 11))))
                               (pick-value-in-array fdp '("" "0" "00"))
                               (consume-integral fdp :u64)
                               (pick-value-in-array fdp '("" "." ".0" ".5" ".12345678" ".123456789"))
                               (pick-value-in-array fdp '("" "9999999999" "e3" "x"))
                               (pick-value-in-array fdp (list "" " " (string (code-char 12))))))))
  "The number parsers every option value and amount goes through agree with
Core's: LocaleIndependentAtoi<int64_t> (atoi's C-locale reading of the longest
integer prefix, saturating at int64) and ParseMoney (trim, digits, an
optional point and at most eight decimals, whole part at most ten digits,
MoneyRange), against reference models of Core's code; and ParseFixedPoint
answers."
  (let ((string (map 'string #'code-char buffer)))
    (let ((ours (bl.cfg:locale-independent-atoi string))
          (core (core-locale-independent-atoi string)))
      (fuzz-assert (eql (fuzz-sabotage ours) core) "LocaleIndependentAtoi(~S): ~S, Core ~S" string ours core))
    (let ((ours (bl.cfg:conf-parse-money string))
          (core (core-parse-money string)))
      (fuzz-assert (eql ours core) "ParseMoney(~S): ~S, Core ~S" string ours core))
    (bl.rpc:parse-fixed-point string 8)
    (bl.rpc:parse-fixed-point string 3)))

;;; --- hex.cpp -----------------------------------------------------------------------

(define-fuzz-target hex
    (buffer :core "hex.cpp:22-64" :iterations 10000 :max-len 80
            :corpus (lambda (fdp)
                      (%octets-of-string
                       (let ((h (bl.crypto:bytes-to-hex (consume-bytes fdp (consume-integral-in-range fdp 0 40)))))
                         (if (consume-bool fdp) (string-upcase h) h)))))
  "A string of hex digits decodes to bytes that print as the same string in
lower case; the uint256 reader (Txid/Wtxid FromHex) takes exactly the
64-digit ones; and DecodeHexBlockHeader / DecodeHexBlk answer."
  (let* ((string (map 'string #'code-char buffer))
         (is-hex (and (evenp (length string)) (every (lambda (c) (digit-char-p c 16)) string))))
    (when is-hex
      (let ((bytes (bl.crypto:hex-to-bytes string)))
        (fuzz-assert (string= (fuzz-sabotage (bl.crypto:bytes-to-hex bytes)) (string-downcase string))
                     "hex ~S prints back as ~S" string (bl.crypto:bytes-to-hex bytes))))
    (handler-case (bl.rpc:decode-hex-tx string) (bl.rpc:rpc-error () nil))
    (let ((bytes (ignore-errors (bl.crypto:hex-to-bytes string))))
      (when bytes
        (fuzz-deserialize (bl.ser:br-read-bitcoin-block (bl.ser:make-byte-reader-from bytes)))))))

;;; --- pow.cpp -------------------------------------------------------------------------

(define-fuzz-target pow-transition
    (buffer :core "pow.cpp:141-175" :iterations 20000 :max-len 40)
  "Whatever the timestamps of a retarget period, the mainnet difficulty
GetNextWorkRequired computes for the next one is a transition
PermittedDifficultyTransition allows -- the bound headers presync relies on."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (old-time (consume-integral fdp :u32))
         (new-time (consume-integral fdp :u32))
         (bits (consume-integral fdp :u32)))
    (with-network (:mainnet)
      (let ((target (bl.store:bits-to-target bits)))
        (when (or (null target) (> target bl.store:*pow-limit-target*))
          (setf bits (bl.store:target-to-bits bl.store:*pow-limit-target*))))
      (let ((new-bits (bl.store:calculate-next-work-required old-time new-time bits)))
        (fuzz-assert (fuzz-sabotage (bl.net:permitted-difficulty-transition :mainnet 2016 bits new-bits))
                     "~8,'0x -> ~8,'0x over ~D s is not a permitted transition"
                     bits new-bits (- new-time old-time))))))

(define-fuzz-target pow
    (buffer :core "pow.cpp:24-139" :iterations 20000 :max-len 40)
  "The compact target encoding: nBits that DeriveTarget accepts decode to a
target whose GetCompact decodes to the same target, and CheckProofOfWork
answers for any header."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (bits (consume-integral fdp :u32)))
    (with-network (:mainnet)
      (let ((target (bl.store:derive-target bits)))
        (when target
          (fuzz-assert (= (fuzz-sabotage (bl.store:bits-to-target (bl.store:target-to-bits target))) target)
                       "nBits ~8,'0x: the target does not survive GetCompact" bits))
        (bl.val:check-proof-of-work (consume-block-header fdp))))))

;;; --- merkleblock.cpp -------------------------------------------------------------

(define-fuzz-target merkleblock
    (buffer :core "merkleblock.cpp:17-49" :iterations 4000 :max-len 400)
  "A partial merkle tree built over any transaction ids and any match set
extracts to the block's merkle root and exactly the matched ids, at their
positions; and ExtractMatches over arbitrary flag bits and hashes answers
without signalling."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (txids (coerce (loop repeat (consume-integral-in-range fdp 1 40) collect (consume-uint256 fdp))
                        'vector))
         (match (map 'vector (lambda (x) (declare (ignore x)) (consume-bool fdp)) txids)))
    (multiple-value-bind (bits hashes) (bl.net:build-partial-merkle-tree txids match)
      (multiple-value-bind (root matched indices)
          (bl.net:extract-partial-merkle-tree (length txids) bits hashes)
        (let ((expected-indices (loop for m across match for i from 0 when m collect i)))
          (if (< (length (remove-duplicates txids :test #'equalp)) (length txids))
              nil ; equal ids: CVE-2012-2459's duplicate, which Extract may refuse
              (progn
                (fuzz-assert (equalp (fuzz-sabotage root)
                                     (bl.val:compute-merkle-root (coerce txids 'list)))
                             "the partial tree's root is not the block's")
                (fuzz-assert (equal indices expected-indices) "matched positions ~S, expected ~S"
                             indices expected-indices)
                (fuzz-assert (equalp matched (mapcar (lambda (i) (aref txids i)) expected-indices))
                             "matched ids differ"))))))
    (bl.net:extract-partial-merkle-tree
     (consume-integral-in-range fdp 0 100)
     (loop repeat (consume-integral-in-range fdp 0 64) collect (consume-bool fdp))
     (loop repeat (consume-integral-in-range fdp 0 8) collect (consume-uint256 fdp)))))

;;; --- blockfilter.cpp ----------------------------------------------------------------

(define-fuzz-target blockfilter
    (buffer :core "blockfilter.cpp:17-49" :iterations 2000 :max-len 400)
  "A BIP158 GCS filter built over any set of elements under any key matches
every one of them, singly and as a set (no false negatives); a query set of
fresh elements answers."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (k0 (consume-integral fdp :u64))
         (k1 (consume-integral fdp :u64))
         (elements (remove-duplicates
                    (loop repeat (consume-integral-in-range fdp 0 60)
                          collect (consume-random-length-byte-vector fdp 16))
                    :test #'equalp))
         (filter (bl.store:build-gcs-filter elements k0 k1)))
    (dolist (e elements)
      (fuzz-assert (fuzz-sabotage (bl.store:gcs-filter-match filter k0 k1 e))
                   "the filter does not match its own element ~A" (bl.crypto:bytes-to-hex e)))
    (when elements
      (fuzz-assert (bl.store:gcs-filter-match-any filter k0 k1 (list (first elements)))
                   "MatchAny misses an element"))
    (bl.store:gcs-filter-match-any filter k0 k1
                                   (loop repeat (consume-integral-in-range fdp 0 10)
                                         collect (consume-random-length-byte-vector fdp 16)))))

;;; --- minisketch.cpp ------------------------------------------------------------------

(define-fuzz-target minisketch
    (buffer :core "minisketch.cpp:26-83" :iterations 600 :max-len 400)
  "Two 32-bit sketches filled from overlapping sets, each round-tripped
through its serialization, merge into the sketch of the symmetric difference,
which decodes -- whenever the capacity holds it, at any element bound between
the difference and the capacity -- to exactly that difference. Capacities up
to 64 (Core draws up to 200) keep a draw within the budget."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (capacity (consume-integral-in-range fdp 1 64))
         (a (bl.net:ms-make-sketch capacity))
         (b (bl.net:ms-make-sketch capacity))
         (diff (make-hash-table)))
    (limited-while ((consume-bool fdp) 10000)
      (let ((entry (consume-integral-in-range fdp 1 (- (ash 1 32) 2) 32)))
        (flet ((keep-diff () (setf (gethash entry diff) (not (gethash entry diff)))))
          (call-one-of fdp
            (progn (bl.net:ms-sketch-add a entry) (keep-diff))
            (progn (bl.net:ms-sketch-add b entry) (keep-diff))
            (progn (bl.net:ms-sketch-add a entry) (bl.net:ms-sketch-add b entry))))))
    (let* ((expected (sort (loop for k being the hash-keys of diff using (hash-value v) when v collect k) #'<))
           (ar (bl.net:ms-sketch-deserialize (bl.net:ms-sketch-serialize a)))
           (br (bl.net:ms-sketch-deserialize (bl.net:ms-sketch-serialize b)))
           (merged (bl.net:ms-sketch-merge (if (consume-bool fdp) a ar) (if (consume-bool fdp) b br))))
      (when (>= capacity (length expected))
        (multiple-value-bind (decoded ok)
            (bl.net:ms-decode merged :max-elements (consume-integral-in-range fdp (length expected) capacity))
          (fuzz-assert ok "a difference of ~D in a capacity-~D sketch did not decode" (length expected) capacity)
          (fuzz-assert (equal (fuzz-sabotage (sort (copy-list decoded) #'<)) expected)
                       "decoded ~S, the difference is ~S" decoded expected))))))
