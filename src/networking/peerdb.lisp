(in-package #:bitcoin-lisp.networking)

;;; Peer address records + shared IP helpers
;;;
;;; The peer-address record and the IP/key utilities used by the address
;;; manager. The manager itself — a Bitcoin Core-style new/tried bucket addrman
;;; — lives in addrman.lisp.

;;;; Data Structures

(defstruct peer-address
  "A known peer address with addrman bucket/reputation metadata (mirrors Bitcoin
Core's AddrInfo). The address-book (see addrman.lisp) is a new/tried bucket
manager; these records are its entries.

Network-typed (BIP155): IP holds the raw address bytes — 16 for IPv4
(IPv4-mapped IPv6, the historical form), IPv6 and CJDNS; 32 for TORv3
(ed25519 pubkey) and I2P (destination hash). NET is :ipv4 :ipv6 :torv3
:i2p or :cjdns, or NIL meaning \"IP, derive IPv4 vs IPv6 from the mapped
bytes\" — the default, so the many plain-IP construction sites need no
:net argument. Read the network via PEER-ADDRESS-NETWORK, never the raw
slot."
  (net nil :type (or null keyword))
  (ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
      :type (simple-array (unsigned-byte 8) (*)))
  (port 0 :type (unsigned-byte 16))
  (services 0 :type (unsigned-byte 64))
  ;; nTime: last time this address was seen advertised (unix seconds).
  (last-seen 0 :type (unsigned-byte 32))
  ;; m_last_try: last time we attempted to connect to it.
  (last-attempt 0 :type (unsigned-byte 32))
  ;; m_last_success: last time we successfully connected.
  (last-success 0 :type (unsigned-byte 32))
  ;; m_last_count_attempt: last attempt counted as a failure (epoch bookkeeping).
  (last-count-attempt 0 :type (unsigned-byte 32))
  ;; Connection attempts since the last success.
  (n-attempts 0 :type (unsigned-byte 32))
  ;; Net-group of the source peer that told us about this address (Core: source).
  (source-group nil :type (or null (simple-array (unsigned-byte 8) (*))))
  ;; The address itself of that source, as (network . address-bytes): Core
  ;; AddrInfo::source, which peers.dat stores (addrman_impl.h:73-76) and the
  ;; group above is derived from. NIL when the entry names itself.
  (source nil :type (or null cons))
  ;; How many NEW buckets reference this entry (0 once it lives in TRIED).
  (ref-count 0 :type (unsigned-byte 8))
  ;; T when the entry lives in the TRIED table.
  (in-tried nil :type boolean)
  ;; Index into the address-book's random-id vector (for O(1) removal).
  (random-pos -1 :type fixnum)
  ;; Internal address-book id (key into the info map).
  (id 0 :type fixnum))

;;;; Address Book Key

(defun ip-network (ip)
  "Derive :ipv4 or :ipv6 from a 16-byte IP's mapped form."
  (if (ipv4-mapped-p ip) :ipv4 :ipv6))

(defun peer-address-network (pa)
  "The network keyword of PA (:ipv4 :ipv6 :torv3 :i2p :cjdns), deriving
IPv4 vs IPv6 from the 16-byte mapped form when the net slot is NIL."
  (or (peer-address-net pa) (ip-network (peer-address-ip pa))))

(defun network-key-id (network)
  "One-byte network discriminator for addrman keys — the BIP155 id."
  (ecase network (:ipv4 1) (:ipv6 2) (:torv3 4) (:i2p 5) (:cjdns 6)))

(defun key-id-network (id)
  "Inverse of network-key-id; NIL for an unrecognized id."
  (case id (1 :ipv4) (2 :ipv6) (4 :torv3) (5 :i2p) (6 :cjdns)))

(defun make-address-key (ip port &optional net)
  "Create an addrman key from address bytes IP, PORT and network NET:
[net-id-byte, address-bytes..., port-hi, port-lo]. NET NIL derives
IPv4/IPv6 from 16-byte mapped IP — the pre-BIP155 call sites, which all
deal in IP peers. Addresses on different networks never collide even
with identical bytes (e.g. a TORv3 pubkey equal to an I2P hash)."
  (let* ((n (length ip))
         (key (make-array (+ n 3) :element-type '(unsigned-byte 8))))
    (setf (aref key 0) (network-key-id (or net (ip-network ip))))
    (replace key ip :start1 1)
    (setf (aref key (+ n 1)) (ldb (byte 8 8) port))
    (setf (aref key (+ n 2)) (ldb (byte 8 0) port))
    key))

;;;; IPv4 Helper

(defun ipv4-to-mapped-ipv6 (a b c d)
  "Convert IPv4 address bytes to IPv4-mapped IPv6 (16 bytes)."
  (let ((ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref ip 10) #xFF)
    (setf (aref ip 11) #xFF)
    (setf (aref ip 12) a)
    (setf (aref ip 13) b)
    (setf (aref ip 14) c)
    (setf (aref ip 15) d)
    ip))

(defun peers-dat-path (data-directory)
  "Return the path to peers.dat in DATA-DIRECTORY."
  (merge-pathnames "peers.dat" data-directory))

;;;; IP String Conversion

(defun ipv4-mapped-p (ip)
  "T if a 16-byte IP is an IPv4-mapped IPv6 address (::ffff:a.b.c.d)."
  (and (= (length ip) 16)
       (loop for i below 10 always (zerop (aref ip i)))
       (= (aref ip 10) #xFF)
       (= (aref ip 11) #xFF)))

(defun ip-bytes-to-string (ip)
  "Convert a 16-byte IP address to a string, as Core's CNetAddr::ToStringAddr
does. IPv4-mapped addresses (::ffff:a.b.c.d) are rendered as a dotted quad;
anything else is IPv6ToString (netaddress.cpp:514-563): lower-case hex groups
without leading zeros, and the LONGEST run of two or more all-zero groups (the
first, on a tie) written as `::'. rpc_net.py:531 expects 2803:0:1234:abcd::1
where the fixed-width form printed 2803:0000:1234:abcd:0000:0000:0000:0001."
  (if (ipv4-mapped-p ip)
      ;; IPv4-mapped
      (format nil "~D.~D.~D.~D" (aref ip 12) (aref ip 13) (aref ip 14) (aref ip 15))
      (let* ((groups (loop for i from 0 below 16 by 2
                           collect (logior (ash (aref ip i) 8) (aref ip (1+ i)))))
             (best-start 0) (best-len 0) (cur-start 0) (cur-len 0))
        ;; Core's ZeroSpan scan: a run only replaces the best when STRICTLY
        ;; longer, so the first of two equal runs wins.
        (loop for g in groups for i from 0
              do (if (/= g 0)
                     (setf cur-start (1+ i) cur-len 0)
                     (progn (incf cur-len)
                            (when (> cur-len best-len)
                              (setf best-start cur-start best-len cur-len)))))
        (with-output-to-string (out)
          (let ((last nil))           ; the last character written, if any
            (loop for g in groups for i from 0
                  do (cond ((and (>= best-len 2) (<= best-start i)
                                 (< i (+ best-start best-len)))
                            (when (= i best-start)
                              (write-string "::" out)
                              (setf last #\:)))
                           (t
                            (when (and last (char/= last #\:))
                              (write-char #\: out))
                            (format out "~(~X~)" g)
                            (setf last #\0)))))))))

(defun %parse-ipv4-string (string)
  "Parse a dotted-quad IPv4 STRING to its 16-byte IPv4-mapped form, or NIL.
Strict: exactly four all-digit components of 1-3 characters, each <= 255
(inet_pton discipline — no signs, spaces or hex)."
  (let ((parts (uiop:split-string string :separator ".")))
    (when (and (= (length parts) 4)
               (every (lambda (p)
                        (and (<= 1 (length p) 3)
                             (every #'digit-char-p p)
                             (<= (parse-integer p) 255)))
                      parts))
      (apply #'ipv4-to-mapped-ipv6 (mapcar #'parse-integer parts)))))

(defun %parse-ipv6-string (string)
  "Parse an IPv6 literal STRING to 16 bytes, or NIL: full colon-hex, at most
one \"::\" compression, and an embedded IPv4 dotted-quad tail in the last 32
bits (\"::ffff:1.2.3.4\", RFC 4291 §2.2.3) — the text forms Bitcoin Core
accepts via inet_pton (netbase LookupHost). Scoped (%zone) forms are rejected."
  (when (find #\% string)
    (return-from %parse-ipv6-string nil))
  (flet ((split (s)
           (when (and s (plusp (length s)))
             (loop for start = 0 then (1+ pos)
                   for pos = (position #\: s :start start)
                   collect (subseq s start (or pos (length s)))
                   while pos)))
         (words (groups final-p)
           ;; GROUPS as a list of 16-bit words; an embedded IPv4 quad is only
           ;; legal as the very last group of the whole address (FINAL-P) and
           ;; contributes two words.
           (loop for (g . rest) on groups
                 append (cond
                          ((find #\. g)
                           (let ((v4 (and (null rest) final-p
                                          (%parse-ipv4-string g))))
                             (unless v4 (return-from %parse-ipv6-string nil))
                             (list (logior (ash (aref v4 12) 8) (aref v4 13))
                                   (logior (ash (aref v4 14) 8) (aref v4 15)))))
                          ((and (<= 1 (length g) 4)
                                (every (lambda (c) (digit-char-p c 16)) g))
                           (list (parse-integer g :radix 16)))
                          (t (return-from %parse-ipv6-string nil))))))
    (let ((double (search "::" string)))
      ;; A second "::" is invalid.
      (when (and double (search "::" string :start2 (1+ double)))
        (return-from %parse-ipv6-string nil))
      (let* ((head (words (split (if double (subseq string 0 double) string))
                          (not double)))
             (tail (words (split (when double (subseq string (+ double 2)))) t))
             (n (+ (length head) (length tail))))
        (when (or (and double (<= n 7))
                  (and (not double) (= n 8)))
          (let ((bytes (make-array 16 :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
            (loop for w in (append head (make-list (- 8 n) :initial-element 0)
                                   tail)
                  for i from 0
                  do (setf (aref bytes (* 2 i)) (ash w -8)
                           (aref bytes (1+ (* 2 i))) (logand w #xFF)))
            bytes))))))

(defun %parse-ipv4-aton (string)
  "Parse STRING in inet_aton's numeric IPv4 notation -- one to four
dot-separated parts, each decimal, 0x-hex or 0-led octal, the LAST part
filling every byte the earlier ones left (\"127.1\" is 127.0.0.1, \"10.65535\"
is 10.0.255.255). Returns the 16-byte mapped form, or NIL. This is what Core's
numeric Lookup accepts on glibc, where getaddrinfo(AI_NUMERICHOST) goes through
inet_aton (netbase.cpp:45-60 WrappedGetAddrInfo; rpc_net.py:252-255 relies on
it)."
  (let ((parts (uiop:split-string string :separator ".")))
    (when (<= 1 (length parts) 4)
      (let ((values
              (loop for part in parts
                    collect (let* ((hex (and (> (length part) 2)
                                             (char= (char part 0) #\0)
                                             (char-equal (char part 1) #\x)))
                                   (octal (and (not hex) (> (length part) 1)
                                               (char= (char part 0) #\0)))
                                   (radix (cond (hex 16) (octal 8) (t 10)))
                                   (digits (if hex (subseq part 2) part)))
                              (if (and (plusp (length digits))
                                       (every (lambda (c) (digit-char-p c radix))
                                              digits))
                                  (parse-integer digits :radix radix)
                                  (return-from %parse-ipv4-aton nil))))))
        (let* ((n (length values))
               (last-max (1- (expt 256 (- 5 n)))))
          (when (and (every (lambda (v) (<= v 255)) (butlast values))
                     (<= (car (last values)) last-max))
            (let ((word (car (last values))))
              (loop for v in (butlast values)
                    for shift downfrom 24 by 8
                    do (incf word (ash v shift)))
              (ipv4-to-mapped-ipv6 (ldb (byte 8 24) word) (ldb (byte 8 16) word)
                                   (ldb (byte 8 8) word) (ldb (byte 8 0) word)))))))))

(defun numeric-host-ip-bytes (string)
  "The 16-byte address a NUMERIC host STRING names (Core LookupNumeric's
host half, netbase.cpp:216-224): any form STRING-TO-IP-BYTES reads, plus
inet_aton's short IPv4 forms. NIL for a hostname."
  (or (string-to-ip-bytes string)
      (%parse-ipv4-aton string)))

(defun string-to-ip-bytes (addr-string)
  "Parse an IP-address string to its 16-byte internal form: an IPv4 dotted
quad (kept as IPv4-mapped IPv6, the historical form) or any IPv6 text form
(see %parse-ipv6-string). Returns NIL for anything else — hostnames,
onion/i2p names, garbage — and never signals."
  (or (%parse-ipv4-string addr-string)
      (when (find #\: addr-string)
        (%parse-ipv6-string addr-string))))
