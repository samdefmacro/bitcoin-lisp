(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/asmap.cpp at the pin: an asmap built from Core's
;;;; IPv4-prefix bytecode (or none, for IPv6) and up to 130 buffer bytes, and
;;;; an address of 4 or 16 bytes; when CheckStandardAsmap accepts the map,
;;;; NetGroupManager::GetMappedAS of the address must answer. A corpus writes
;;;; maps that are sane after the prefix (asmap-direct.lisp's trie encoder),
;;;; since random bytes almost never are. Ours:
;;;; ASMAP-SANE-P over 128 bits and ASMAP-ASN under the map. Beyond Core: an
;;;; answer is an ASN (1 or more) or no mapping, never 0 or anything else.

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

(define-fuzz-target asmap
    (buffer :core "asmap.cpp:18-43" :corpus #'%asmap-corpus :iterations 6000 :max-len 160)
  "A map Core's CheckStandardAsmap accepts maps any address to an ASN or to
nothing."
  (when (< (length buffer) 8) (fuzz-reject))
  (let* ((size (+ 3 (logand (aref buffer 0) 127)))
         (ipv6 (logbitp 7 (aref buffer 0)))
         (addr-size (if ipv6 16 4)))
    (when (< (length buffer) (+ 1 size addr-size)) (fuzz-reject))
    (let ((map (%concat-octets (list (if ipv6 #() +ipv4-prefix-asmap+) (subseq buffer 1 (1+ size)))))
          (addr (subseq buffer (1+ size) (+ 1 size addr-size))))
      (when (bl.net:asmap-sane-p map 128)
        (let* ((ip (if ipv6 addr (bl.net:ipv4-to-mapped-ipv6 (aref addr 0) (aref addr 1) (aref addr 2) (aref addr 3))))
               (asn (let ((bl.net:*asmap* map)) (bl.net:asmap-asn ip (if ipv6 :ipv6 :ipv4)))))
          (fuzz-assert (or (null asn) (and (integerp asn) (plusp (fuzz-sabotage asn))))
                       "GetMappedAS answered ~S" asn))))))
