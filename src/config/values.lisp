(in-package #:bitcoin-lisp.config)

;;;; Option values (Core common/args.cpp, util/strencodings.cpp)
;;;
;;; The parsers a single option value goes through: locale-independent
;;; integers, Core's boolean spellings, money, hex, byte units, log levels,
;;; proxy specs, network names and -bind addresses -- and the -listen
;;; interactions derived from them. Pure functions of strings; nothing here
;;; reads a special.

(defun locale-independent-atoi (value)
  "Core LocaleIndependentAtoi (util/strencodings.h:118-143), the integer
interpretation the config system is built on.

Emulates C-locale atoi: trim, allow one leading `+` (but `+-` is 0), then take
the LONGEST INTEGER PREFIX. No digits at all is 0 — which is the whole reason
this function has to exist here rather than being approximated, because
`atoi(\"true\")` is 0 and therefore `true` is FALSE to Bitcoin Core."
  (let* ((s (string-trim '(#\Space #\Tab #\Return #\Newline #\Page) value))
         (start 0)
         (len (length s)))
    (when (and (< start len) (char= (char s start) #\+))
      (when (and (< (1+ start) len) (char= (char s (1+ start)) #\-))
        (return-from locale-independent-atoi 0))
      (incf start))
    (let ((sign 1))
      (when (and (< start len) (member (char s start) '(#\+ #\-)))
        (when (char= (char s start) #\-) (setf sign -1))
        (incf start))
      (let ((end start))
        (loop while (and (< end len) (digit-char-p (char s end))) do (incf end))
        (if (= end start)
            0
            (* sign (parse-integer s :start start :end end)))))))

(defun conf-parse-bool (value)
  "Interpret a config VALUE as a boolean, exactly as Core's InterpretBool
 (common/args.cpp:57-62): the empty string (a bare -flag) is true, otherwise
`LocaleIndependentAtoi(value) != 0`.

This is deliberately NOT the lenient reading it looks like it should be. We
used to accept \"true\"/\"yes\"/\"on\" as true and treat any unrecognized value as
true; Core parses those to 0 and calls them FALSE. So the same bitcoin.conf
saying `server=true` opened a listener on our node and left it closed on
Core's — a silent, opposite-direction divergence on a security-relevant flag."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (if (string= v "")
        t
        (/= 0 (locale-independent-atoi v)))))

(defun conf-parse-int (value)
  "Parse a config VALUE as an integer, or signal an error."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (handler-case (parse-integer v)
      (error () (config-error "Invalid integer config value: ~S" value)))))

(defun log-categories-string ()
  "Core's LogCategoriesString: every category name, comma-separated, for the
-loglevel error message."
  (format nil "~{~A~^, ~}" (sort (copy-list bl.log:+log-categories+) #'string<)))

(defun parse-loglevel-spec (value)
  "Parse one -loglevel value. Returns (VALUES category level), with CATEGORY NIL
for the global form.

Core splits on the first ':' at index 3 or later (init/common.cpp:63), which is
how `-loglevel=net:debug` is told from a bare level; a level name is never long
enough to contain one there. Both halves must be known, and an unknown one is a
fatal init error — the option silently doing nothing is how an operator ends up
staring at a log that will never contain what they asked for."
  (let ((colon (position #\: value :start (min 3 (length value)))))
    (if colon
        (let ((category (string-downcase (subseq value 0 colon)))
              (level (subseq value (1+ colon))))
          (unless (and (bl.log:log-category-known-p category)
                       (member (string-downcase level)
                               '("info" "debug" "trace" "warn" "warning" "error")
                               :test #'string=))
            (config-error "Unsupported category-specific logging level -loglevel=~A. ~
Expected -loglevel=<category>:<loglevel>. Valid categories: ~A. ~
Valid loglevels: info, debug, trace." value (log-categories-string)))
          (values category (conf-parse-loglevel level)))
        (values nil (conf-parse-loglevel value)))))

(defun conf-parse-loglevel-global (value)
  "The GLOBAL threshold a -loglevel value implies, or NIL when it names a
category instead. A category-specific spec leaves the global level alone."
  (multiple-value-bind (category level) (parse-loglevel-spec value)
    (and (null category) level)))

(defun conf-parse-loglevel (value)
  "Map a -loglevel value to one of :debug :info :warn :error."
  (let ((v (string-downcase (string-trim '(#\Space #\Tab) value))))
    (cond ((member v '("debug" "trace") :test #'string=) :debug)
          ((string= v "info") :info)
          ((member v '("warn" "warning") :test #'string=) :warn)
          ((member v '("error" "none") :test #'string=) :error)
          ;; Core's wording verbatim, list included (init/common.cpp:66,
          ;; LogLevelsString). feature_logging.py matches it as a FULL regex.
          ;; Core's settable levels are exactly info, debug and trace — warn and
          ;; error exist as LEVELS but are not offered as a global threshold, so
          ;; they are accepted here (nothing should start refusing a config that
          ;; worked) and simply not named among the valid values.
          (t (config-error "Unsupported global logging level -loglevel=~A. ~
Valid values: info, debug, trace." value)))))

(defun conf-parse-money (value)
  "Parse a config VALUE as a BTC amount string into satoshis (Bitcoin Core
ParseMoney, util/moneystr.cpp): optional whitespace, digits, optional '.'
plus up to 8 decimal digits. Returns NIL for anything else (negative,
malformed, >8 decimals, out of range) — callers turn that into their own
AmountErrMsg-style error."
  (let* ((v (string-trim '(#\Space #\Tab) value))
         (dot (position #\. v)))
    (flet ((digits-p (s) (and (plusp (length s)) (every #'digit-char-p s))))
      (let ((whole (if dot (subseq v 0 dot) v))
            (frac (if dot (subseq v (1+ dot)) "")))
        (when (and (digits-p whole)
                   (or (null dot) (digits-p frac))
                   (<= (length frac) 8))
          (let ((sats (+ (* (parse-integer whole) 100000000)
                         (if (plusp (length frac))
                             (* (parse-integer frac)
                                (expt 10 (- 8 (length frac))))
                             0))))
            (when (<= sats 2100000000000000) ; MAX_MONEY
              sats)))))))

(defun conf-parse-user-hex (value)
  "Core uint256::FromUserHex (uint256.h:165-176) as raw bytes: strip an
optional 0x prefix, accept UP TO 64 hex digits, left-pad with zeros to 32
bytes. Returns the 32 bytes in DISPLAY order (most significant first), or
NIL for non-hex / over-long input."
  (let* ((v (string-trim '(#\Space #\Tab) value))
         (v (if (and (> (length v) 1)
                     (char= (char v 0) #\0)
                     (char-equal (char v 1) #\x))
                (subseq v 2)
                v)))
    (when (and (<= (length v) 64)
               (every (lambda (c) (digit-char-p c 16)) v))
      (let ((padded (concatenate 'string
                                 (make-string (- 64 (length v)) :initial-element #\0)
                                 v)))
        (bl.crypto:hex-to-bytes padded)))))

;;; -uacomment / BIP14 subversion (Core init.cpp:1676-1686)

(defconstant +max-subversion-length+ 256
  "Cap on the full formatted subversion string (Core MAX_SUBVERSION_LENGTH,
net.h:67). Exceeding it is an init ERROR, not a truncation.")

(defun ua-comment-safe-p (comment)
  "T when COMMENT survives Core's SanitizeString with SAFE_CHARS_UA_COMMENT
unchanged (strencodings.cpp:25: alphanumerics plus \" .,;-_?@\"). An unsafe
character makes -uacomment an init error, matching Core."
  (every (lambda (c)
           (or (alphanumericp c) (find c " .,;-_?@")))
         comment))

(defconstant +default-proxy-port+ 9050
  "Default SOCKS5 proxy port when -proxy/-onion gives no :port (Tor's SOCKS
port; Bitcoin Core init.cpp:1721 Lookup(..., 9050, ...)).")

(defun conf-parse-proxy (value)
  "Parse a -proxy/-onion VALUE \"ip[:port]\" into (values host port), with
PORT defaulting to 9050. Returns NIL for \"0\" or the empty string — Core's
-noproxy / -proxy=0 'remove the proxy' convention (init.cpp:1700-1704).
Accepts \"[ipv6]:port\" / \"[ipv6]\"; a trailing :port is only honored when it
is all digits after a single colon, so a bare IPv6 address is host-only
(same splitting rules as parse-node-endpoint, node/peers.lisp)."
  (let ((v (string-trim '(#\Space #\Tab) value)))
    (cond
      ((or (zerop (length v)) (string= v "0")) nil)
      ;; [ipv6]:port or [ipv6]
      ((char= (char v 0) #\[)
       (let ((close (position #\] v)))
         (if close
             (let ((host (subseq v 1 close))
                   (rest (subseq v (1+ close))))
               (if (and (plusp (length rest)) (char= (char rest 0) #\:)
                        (plusp (length (subseq rest 1)))
                        (every #'digit-char-p (subseq rest 1)))
                   (values host (parse-integer rest :start 1))
                   (values host +default-proxy-port+)))
             (values v +default-proxy-port+))))
      (t
       (let ((colon (position #\: v :from-end t)))
         (if (and colon
                  (< (1+ colon) (length v))
                  (every #'digit-char-p (subseq v (1+ colon)))
                  ;; A single colon => host:port; multiple => bare IPv6.
                  (= colon (position #\: v)))
             (values (subseq v 0 colon) (parse-integer v :start (1+ colon)))
             (values v +default-proxy-port+)))))))

(defun conf-parse-byte-units (value &optional (default-unit #\M))
  "Core ParseByteUnits (common/args.cpp): a byte count with an optional
[k|K|m|M|g|G|t|T] suffix, LOWERCASE being 1000-base and UPPERCASE 1024-base.
DEFAULT-UNIT applies when there is no suffix — M for -maxuploadtarget, which is
why a bare 100 there means 100 MiB and not 100 bytes. Pass #\B for Core's
ByteUnit::NOOP, where a bare number is a byte count."
  (let* ((v (string-trim '(#\Space #\Tab) value))
         (last (and (plusp (length v)) (char v (1- (length v)))))
         (suffixed (and last (find last "kKmMgGtT")))
         (unit (if suffixed last default-unit))
         (digits (if suffixed (subseq v 0 (1- (length v))) v))
         (multiplier (ecase unit
                       ;; Core's ByteUnit::NOOP, the default for every option
                       ;; other than -maxuploadtarget.
                       (#\B 1)
                       (#\k 1000) (#\K 1024)
                       (#\m (expt 1000 2)) (#\M (expt 1024 2))
                       (#\g (expt 1000 3)) (#\G (expt 1024 3))
                       (#\t (expt 1000 4)) (#\T (expt 1024 4)))))
    (unless (and (plusp (length digits)) (every #'digit-char-p digits))
      (config-error "Unable to parse byte amount: '~A'" value))
    (* (parse-integer digits) multiplier)))

(defun conf-parse-network-name (value)
  "Map an -onlynet VALUE to a network keyword (Core ParseNetwork,
netbase.cpp: ipv4/ipv6/onion/i2p/cjdns; the old \"tor\" alias is gone)."
  (let ((v (string-downcase (string-trim '(#\Space #\Tab) value))))
    (cond ((string= v "ipv4") :ipv4)
          ((string= v "ipv6") :ipv6)
          ((string= v "onion") :torv3)
          ((string= v "i2p") :i2p)
          ((string= v "cjdns") :cjdns)
          (t (config-error "Unknown network specified in -onlynet: ~S" value)))))

(defun conf-section-name (network)
  "The bitcoin.conf [section] header that scopes options to NETWORK
(chain-params-core-name: main, test, testnet4, signet, regtest)."
  (bl.chain:chain-params-core-name (bl.chain:find-chain-params network)))

(defun parse-bind-option (spec)
  "Parse one -bind value into (VALUES host port onion-p), or NIL when it is
unparseable.

Core's form is `-bind=<addr>[:<port>][=onion]` (init.cpp; test_node.py:272-276
passes both the plain and the =onion form). The `=onion` suffix marks a
listener reserved for incoming Tor connections rather than an address in its
own right, so it is reported separately. PORT is NIL when the value names only
an address, which means \"the network's default port\".

An IPv6 literal must be bracketed for the port to be separable, exactly as in
Core: `[::1]:8333` has a port, `::1` does not."
  (when (stringp spec)
    (let* ((onion-p nil)
           (text spec))
      ;; The =onion suffix first: it is not part of the address.
      (let ((tail (search "=onion" text :from-end t)))
        (when (and tail (= tail (- (length text) 6)))
          (setf onion-p t text (subseq text 0 tail))))
      (when (plusp (length text))
        (let ((close-bracket (position #\] text :from-end t)))
          (cond
            ;; [v6]:port or bare [v6]
            ((and (char= (char text 0) #\[) close-bracket)
             (let ((host (subseq text 1 close-bracket))
                   (rest (subseq text (1+ close-bracket))))
               (cond ((zerop (length rest)) (values host nil onion-p))
                     ((and (char= (char rest 0) #\:)
                           (%parse-port (subseq rest 1)))
                      (values host (%parse-port (subseq rest 1)) onion-p)))))
            ;; An unbracketed value with exactly one colon is host:port; more
            ;; than one colon is a bare IPv6 literal, never host:port.
            (t
             (let ((colon (position #\: text)))
               (cond ((null colon) (values text nil onion-p))
                     ((find #\: text :start (1+ colon)) (values text nil onion-p))
                     (t (let ((port (%parse-port (subseq text (1+ colon)))))
                          (when port
                            (values (subseq text 0 colon) port onion-p)))))))))))))

(defun %parse-port (string)
  "STRING as a TCP port number, or NIL."
  (when (and (plusp (length string))
             (every #'digit-char-p string))
    (let ((n (parse-integer string :junk-allowed t)))
      (when (and n (<= 1 n 65535)) n))))

(defun conf-effective-listen-flags (alist)
  "Replay Core's -listen/-listenonion soft-set chain over a merged config
ALIST. Returns (VALUES listen-p listen-onion-p). The ONE encoding of this
chain — the start-node plist assembly and apply-config-globals' -onlynet=onion
gate both derive from it, so the two can never drift.

ORDER IS THE WHOLE THING. Core's SoftSetBoolArg is FIRST-WINS: it sets a value
only if nothing has set one yet, and an explicit user value counts as already
set. InitParameterInteraction (init.cpp:764-810) then runs the interactions in
an order chosen so the earlier ones override the later ones:

  1. -bind / -whitebind soft-set -listen=1 (:768-775). Core's comment says why
     in as many words: \"when specifying an explicit binding address, you want
     to listen on it even when -connect or -proxy is specified\".
  2. -connect in any form, or -maxconnections<=0, soft-sets -dnsseed=0 and
     -listen=0 (:777-784) — \"when only connecting to trusted nodes, do not
     seed via DNS, or listen by default\".
  3. -proxy soft-sets -listen=0, to protect privacy (:786-790).

So -bind BEATS -connect, and this is not a corner case: Core's functional test
framework writes both `bind=127.0.0.1` and `connect=0` into every node's config
(test_framework/util.py), and relies on the node listening anyway so that
connect_nodes can wire the network up with `addnode onetry`. Applying step 2
without step 1 leaves every node deaf, every multi-node test times out in
connect_nodes, and the node logs nothing wrong because from its own point of
view it did what it was told.

-listen=0 then soft-disables -listenonion (:808-809), and the explicit
contradiction -listen=0 -listenonion=1 is an init ERROR (:1022-1024)."
  (flet ((lk (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    (let ((listen nil))                 ; NIL = nothing has set it yet
      (flet ((soft-set (value)
               ;; SoftSetBoolArg: first writer wins.
               (unless listen (setf listen (list value)))))
        ;; An explicit -listen is already set before any interaction runs.
        (let ((explicit (lk "listen")))
          (when explicit (soft-set (and (conf-parse-bool explicit) t))))
        (when (or (lk "bind") (lk "whitebind"))
          (soft-set t))
        (when (or (assoc "connect" alist :test #'string=)
                  (let ((m (lk "maxconnections")))
                    (and m (let ((n (parse-integer m :junk-allowed t)))
                             (and n (<= n 0))))))
          (soft-set nil))
        (when (let ((v (lk "proxy"))) (and v (conf-parse-proxy v)))
          (soft-set nil)))
      (let* ((listen-p (if listen (first listen) t)) ; Core DEFAULT_LISTEN
             (lo (lk "listenonion"))
             (lo-p (and lo (conf-parse-bool lo))))
        (when (and (not listen-p) lo-p)
          (config-error "Cannot set -listen=0 together with -listenonion=1"))
        (values listen-p
                (and listen-p (if lo lo-p t)))))))
