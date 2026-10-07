(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/asmap.cpp at the pin: an asmap built from Core's
;;;; IPv4-prefix bytecode (or none, for IPv6) and up to 130 buffer bytes, and
;;;; an address of 4 or 16 bytes; when CheckStandardAsmap accepts the map,
;;;; NetGroupManager::GetMappedAS of the address must answer. A corpus writes
;;;; maps that are sane after the prefix (asmap-direct.lisp's trie encoder),
;;;; since random bytes almost never are. Ours:
;;;; ASMAP-SANE-P over 128 bits and ASMAP-ASN under the map. Beyond Core: the
;;;; answer is Interpret's on GetMappedAS's 128-bit key, restated here, or no
;;;; mapping for Interpret's 0.

(def-suite :fuzz-asmap-tests :in :bitcoin-lisp-tests
  :description "Core fuzz asmap.cpp")

(in-suite :fuzz-asmap-tests)

(defparameter +ipv4-prefix-asmap+ (bl.crypto:hex-to-bytes "fb03ec0fb03fc0fe00fb03ec0fb03fc0fe00fb03ec0fb0fffffeff")
  "Core IPV4_PREFIX_ASMAP (asmap.cpp:16): bytecode that matches ::ffff:0:0/96.")

(defun %asmap-corpus (fdp)
  "Core's encoding for a map that is sane after the prefix: a random trie of
ASNs over the remaining address bits (%ASMAP-ENCODE-TRIE), a size byte that
says how long it is, and an address."
  (let* ((ipv6 (consume-bool fdp))
         (map (%asmap-bits-to-bytes (%asmap-encode-trie (%asmap-random-trie fdp (consume-integral-in-range fdp 1 8)))))
         (map (subseq map 0 (min 130 (length map)))))
    (%concat-octets (list (vector (logior (- (max 3 (length map)) 3) (if ipv6 128 0)))
                          map
                          (consume-bytes fdp (if ipv6 16 4))))))

(defun %mapped-as-key (ip)
  "GetMappedAS's lookup key (netgroup.cpp:82-106): an address carrying an IPv4
one -- IPv4-mapped, RFC6145 or RFC6052 in its last four bytes, 6to4 in bytes
2-5, Teredo bit-flipped in its last four (netaddress.cpp:652-673) -- as
::ffff:a.b.c.d, any other on its own sixteen bytes."
  (flet ((prefix-p (bytes) (equalp (subseq ip 0 (length bytes)) (coerce bytes 'vector))))
    (let ((v4 (cond ((or (prefix-p '(0 0 0 0 0 0 0 0 0 0 #xff #xff))
                         (prefix-p '(0 0 0 0 0 0 0 0 #xff #xff 0 0))
                         (prefix-p '(0 #x64 #xff #x9b 0 0 0 0 0 0 0 0)))
                     (subseq ip 12 16))
                    ((prefix-p '(#x20 #x02)) (subseq ip 2 6))
                    ((prefix-p '(#x20 #x01 0 0)) (map 'vector (lambda (b) (logxor b #xff)) (subseq ip 12 16))))))
      (if v4
          (bl.net:ipv4-to-mapped-ipv6 (aref v4 0) (aref v4 1) (aref v4 2) (aref v4 3))
          ip))))

(define-fuzz-target asmap
    (buffer :core "asmap.cpp:18-43" :corpus #'%asmap-corpus :iterations 6000 :max-len 160)
  "Under a map Core's CheckStandardAsmap accepts, any address maps to what
Interpret answers for GetMappedAS's 128-bit key, or to nothing for 0."
  (when (< (length buffer) 8) (fuzz-reject))
  (let* ((size (+ 3 (logand (aref buffer 0) 127)))
         (ipv6 (logbitp 7 (aref buffer 0)))
         (addr-size (if ipv6 16 4)))
    (when (< (length buffer) (+ 1 size addr-size)) (fuzz-reject))
    (let ((map (%concat-octets (list (if ipv6 #() +ipv4-prefix-asmap+) (subseq buffer 1 (1+ size)))))
          (addr (subseq buffer (1+ size) (+ 1 size addr-size))))
      (when (bl.net:asmap-sane-p map 128)
        (let* ((ip (if ipv6 addr (bl.net:ipv4-to-mapped-ipv6 (aref addr 0) (aref addr 1) (aref addr 2) (aref addr 3))))
               (asn (let ((bl.net:*asmap* map)) (bl.net:asmap-asn ip (if ipv6 :ipv6 :ipv4))))
               (expected (let ((n (bl.net:asmap-interpret map (%mapped-as-key ip))))
                           (and (plusp n) n))))
          (fuzz-assert (equal (fuzz-sabotage asn) expected)
                       "GetMappedAS answered ~S, Interpret on its 128-bit key ~S" asn expected))))))
