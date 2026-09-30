(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/banman.cpp at the pin: random bans, unbans, clears
;;;; and discouragements on the ban manager, then the ban list dumped to
;;;; banlist.json and read back by a fresh one. Ours is the ban list in
;;;; BL.NET (BAN-ADDRESS, UNBAN-ADDRESS, CLEAR-BAN-LIST, LIST-BANS,
;;;; SAVE-BANLIST, LOAD-BANLIST) and the discourage filter; it is process-wide,
;;;; so the target binds the list and its path and clears the filter on both
;;;; sides.

(def-suite :fuzz-banman-tests :in :bitcoin-lisp-tests
  :description "Core fuzz banman.cpp over our ban list and discourage filter")

(in-suite :fuzz-banman-tests)

(defun %fuzz-net-addr-string (fdp)
  "Core ConsumeNetAddr (test/fuzz/util/net.cpp), as the string our ban list
takes: an address of any network the node knows, or a string from the
buffer."
  (call-one-of fdp
    (let ((ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref ip 10) #xff (aref ip 11) #xff)
      (replace ip (consume-bytes fdp 4) :start1 12)
      (bl.net:network-address-to-string :ipv4 ip))
    (bl.net:network-address-to-string :ipv6 (consume-uint128 fdp))
    (bl.net:network-address-to-string :torv3 (consume-uint256 fdp))
    (bl.net:network-address-to-string :i2p (consume-uint256 fdp))
    (let ((ip (consume-uint128 fdp)))
      (setf (aref ip 0) #xfc)
      (bl.net:network-address-to-string :cjdns ip))
    (consume-random-length-string fdp 64)))

(defun %fuzz-subnet-string (fdp)
  "Core ConsumeSubNet, as a CIDR string: an address and a prefix length that
may or may not suit its network."
  (format nil "~A/~D" (%fuzz-net-addr-string fdp) (consume-integral-in-range fdp 0 140)))

(defun %ban-rows ()
  "LIST-BANS as (address created until) rows."
  (mapcar (lambda (b) (list (car b) (bl.net:ban-entry-created (cdr b)) (bl.net:ban-entry-until (cdr b))))
          (bl.net:list-bans)))

(define-fuzz-target banman
    (buffer :core "banman.cpp:42-139" :iterations 400 :max-len 600)
  "Whatever was banned, unbanned, cleared or discouraged, a ban on a
well-formed address or range holds until it expires, an unban erases exactly
that range, a clear empties the list, a discouraged address stays
discouraged, and the list dumped to banlist.json reads back identical --
every range, creation time and expiry -- into a fresh ban manager."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-temp-directory (dir "fuzz-banman")
      (let* ((bl.ser:*mock-time* (consume-integral-in-range fdp 1231006505 4000000000))
             (bl.net:*banned-peers* (make-hash-table :test 'equal))
             (path (merge-pathnames "banlist.json" dir))
             (bl.net:*banlist-path* path))
        (bl.net:clear-discouraged)
        (unwind-protect
             (progn
               (when (consume-bool fdp)
                 ;; start_with_corrupted_banlist
                 (with-open-file (out path :direction :output :if-exists :supersede)
                   (write-string (consume-random-length-string fdp 200) out))
                 (bl.net:load-banlist path))
               (limited-while ((%fuzz-continue-p fdp) 300)
                 (call-one-of fdp
                   (let ((addr (%fuzz-net-addr-string fdp))
                         (seconds (consume-integral-in-range fdp (- (ash 1 31)) (1- (ash 1 31)))))
                     (when (and (bl.net:ban-address addr seconds) (plusp seconds))
                       (fuzz-assert (fuzz-sabotage (bl.net:peer-banned-p addr))
                                    "~S banned for ~D s is not banned" addr seconds)))
                   (let ((subnet (%fuzz-subnet-string fdp))
                         (seconds (consume-integral-in-range fdp (- (ash 1 31)) (1- (ash 1 31)))))
                     (when (and (bl.net:ban-address subnet seconds) (plusp seconds))
                       (fuzz-assert (bl.net:subnet-exactly-banned-p subnet)
                                    "range ~S banned for ~D s is not on the list" subnet seconds)))
                   (progn (bl.net:clear-ban-list)
                          (fuzz-assert (null (bl.net:list-bans)) "a cleared ban list holds entries"))
                   (bl.net:peer-banned-p (%fuzz-net-addr-string fdp))
                   (bl.net:subnet-exactly-banned-p (%fuzz-subnet-string fdp))
                   (let ((addr (%fuzz-net-addr-string fdp)))
                     (bl.net:unban-address addr)
                     (fuzz-assert (not (bl.net:subnet-exactly-banned-p addr))
                                  "~S is still on the list after its unban" addr))
                   (let ((subnet (%fuzz-subnet-string fdp)))
                     (bl.net:unban-address subnet)
                     (fuzz-assert (not (bl.net:subnet-exactly-banned-p subnet))
                                  "range ~S is still on the list after its unban" subnet))
                   (bl.net:list-bans)
                   (bl.net:save-banlist path)
                   (let ((addr (%fuzz-net-addr-string fdp)))
                     (bl.net:discourage-peer addr)
                     (fuzz-assert (bl.net:peer-discouraged-p addr) "~S discouraged is not" addr))
                   (bl.net:peer-discouraged-p (%fuzz-net-addr-string fdp))))
               ;; Dump, move the clock, and read the dump into a fresh list.
               (bl.net:save-banlist path)
               (setf bl.ser:*mock-time* (consume-integral-in-range fdp 1231006505 4000000000))
               (let ((before (%ban-rows)))
                 (let ((bl.net:*banned-peers* (make-hash-table :test 'equal)))
                   (bl.net:load-banlist path)
                   (let ((after (%ban-rows)))
                     (fuzz-assert (equal (fuzz-sabotage before) after)
                                  "the ban list ~S reads back from banlist.json as ~S" before after)))))
          (bl.net:clear-discouraged))))))
