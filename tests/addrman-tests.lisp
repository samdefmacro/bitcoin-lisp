(in-package #:bitcoin-lisp.tests)

;;; Address manager (new/tried bucket addrman) tests.
;;;
;;; Bucket determinism + grouping, Add/Good/Attempt placement and promotion,
;;; Select/GetAddr behavior, and the eclipse-resistance properties: any single
;;; source-group occupies at most 64 of the 1024 new buckets, and flooding new
;;; addresses can never evict the tried table.

(in-suite :addrman-tests)

;;;; Helpers

(defun %ab ()
  "A fresh address book with a fixed (deterministic) bucket key."
  (let ((k (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32) (setf (aref k i) (mod (* i 7) 256)))
    (bitcoin-lisp.networking:make-address-book :key k)))

(defun %ip (a b c d) (bitcoin-lisp.networking:ipv4-to-mapped-ipv6 a b c d))

(defun %now () (bitcoin-lisp.serialization:get-unix-time))

(defun %pa (a b c d &key (port 8333) (services 1) (last-seen (%now)))
  (bitcoin-lisp.networking:make-peer-address
   :ip (%ip a b c d) :port port :services services :last-seen last-seen))

(defun %ipv6 (&rest first-bytes)
  (let ((ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for b in first-bytes for i from 0 do (setf (aref ip i) b))
    ip))

;;;; Grouping

(test net-group-key-ipv4-is-slash16
  (is (equal '(1 203 0)
             (coerce (bitcoin-lisp.networking:net-group-key (%ip 203 0 113 5)) 'list))))

(test net-group-key-ipv6-is-slash32
  (is (equal '(2 #x20 #x01 #x0d #xb8)
             (coerce (bitcoin-lisp.networking:net-group-key
                      (%ipv6 #x20 #x01 #x0d #xb8 #xab #xcd))
                     'list))))

;;;; Bucket functions

(test buckets-deterministic-and-in-range
  (let* ((book (%ab)) (pa (%pa 1 2 3 4))
         (sg (bitcoin-lisp.networking:net-group-key (%ip 9 9 9 9))))
    (is (= (bitcoin-lisp.networking::new-bucket book pa sg)
           (bitcoin-lisp.networking::new-bucket book pa sg)))
    (is (<= 0 (bitcoin-lisp.networking::new-bucket book pa sg) 1023))
    (is (= (bitcoin-lisp.networking::tried-bucket book pa)
           (bitcoin-lisp.networking::tried-bucket book pa)))
    (is (<= 0 (bitcoin-lisp.networking::tried-bucket book pa) 255))
    (is (<= 0 (bitcoin-lisp.networking::bucket-position book pa t 0) 63))))

;;;; Add / Good / Attempt

(test add-creates-new-entry
  (let ((book (%ab)))
    (is-true (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4)))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (is (= 1 (bitcoin-lisp.networking::address-book-n-new book)))
    (is (= 0 (bitcoin-lisp.networking::address-book-n-tried book)))
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
      (is (not (null pa)))
      (is (= 1 (bitcoin-lisp.networking:peer-address-ref-count pa)))
      (is (null (bitcoin-lisp.networking:peer-address-in-tried pa))))))

(test add-rejects-unroutable
  (let ((book (%ab)))
    (is (null (bitcoin-lisp.networking:address-book-add
               book (bitcoin-lisp.networking:make-peer-address
                     :ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                     :port 8333))))
    (is (= 0 (bitcoin-lisp.networking:address-book-count book)))))

(test good-promotes-new-to-tried
  (let ((book (%ab)))
    (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4))
    (is-true (bitcoin-lisp.networking:address-book-good book (%ip 1 2 3 4) 8333))
    (is (= 0 (bitcoin-lisp.networking::address-book-n-new book)))
    (is (= 1 (bitcoin-lisp.networking::address-book-n-tried book)))
    (is (= 1 (bitcoin-lisp.networking:address-book-count book)))
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
      (is-true (bitcoin-lisp.networking:peer-address-in-tried pa))
      (is (= 0 (bitcoin-lisp.networking:peer-address-ref-count pa))))))

(test attempt-counts-failures
  (let ((book (%ab)))
    (bitcoin-lisp.networking:address-book-add book (%pa 1 2 3 4))
    (bitcoin-lisp.networking:address-book-attempt book (%ip 1 2 3 4) 8333 :count-failure t)
    (let ((pa (bitcoin-lisp.networking:address-book-lookup book (%ip 1 2 3 4) 8333)))
      (is (= 1 (bitcoin-lisp.networking:peer-address-n-attempts pa))))))

;;;; Quality

(test terrible-when-ancient
  (is-true (bitcoin-lisp.networking:addr-info-terrible-p (%pa 1 2 3 4 :last-seen 1000) (%now))))

(test not-terrible-when-recent
  (let ((now (%now)))
    (is (null (bitcoin-lisp.networking:addr-info-terrible-p (%pa 1 2 3 4 :last-seen now) now)))))

;;;; Select / GetAddr

(test select-returns-known-address
  (let ((book (%ab)))
    (dotimes (i 5) (bitcoin-lisp.networking:address-book-add book (%pa 10 0 0 i)))
    (is (not (null (bitcoin-lisp.networking:address-book-select book))))))

(test select-empty-book-is-nil
  (is (null (bitcoin-lisp.networking:address-book-select (%ab)))))

(test get-addr-skips-terrible
  (let ((book (%ab)))
    (bitcoin-lisp.networking:address-book-add book (%pa 10 0 0 1 :last-seen (%now)))
    (bitcoin-lisp.networking:address-book-add book (%pa 10 0 0 2 :last-seen 1000)) ; ancient
    (let ((addrs (bitcoin-lisp.networking:address-book-get-addr book :max 0 :pct 100)))
      (is (= 1 (length addrs)))
      (is (equalp (%ip 10 0 0 1)
                  (bitcoin-lisp.networking:peer-address-ip (first addrs)))))))

(test get-addr-respects-max
  (let ((book (%ab)))
    (dotimes (i 20) (bitcoin-lisp.networking:address-book-add book (%pa 12 0 0 i)))
    (is (<= (length (bitcoin-lisp.networking:address-book-get-addr book :max 5 :pct 100)) 5))))

;;;; Eclipse resistance

(test one-source-group-bounded-to-64-new-buckets
  "Every address learned from a single source-group lands in at most 64 of the
1024 new buckets — an attacker flooding from one source can poison only 64."
  (let* ((book (%ab))
         (sg (bitcoin-lisp.networking:net-group-key (%ip 6 6 6 6)))
         (buckets (make-hash-table)))
    (dotimes (i 600)
      (let ((pa (%pa (+ 11 (mod i 200)) (mod (floor i 200) 256) (mod i 251) (mod i 241))))
        (setf (gethash (bitcoin-lisp.networking::new-bucket book pa sg) buckets) t)))
    (is (<= (hash-table-count buckets) 64))))

(test tried-table-survives-new-flood
  "Flooding new addresses (even all from one source) never evicts tried entries."
  (let ((book (%ab)))
    (dotimes (i 3)
      (bitcoin-lisp.networking:address-book-add book (%pa 20 0 0 i))
      (bitcoin-lisp.networking:address-book-good book (%ip 20 0 0 i) 8333))
    (let ((tried-before (bitcoin-lisp.networking::address-book-n-tried book))
          (src (%ip 7 7 7 7)))
      (is (> tried-before 0))
      (dotimes (i 400)
        (bitcoin-lisp.networking:address-book-add
         book (%pa (+ 100 (mod i 150)) (mod (floor i 150) 256) (mod i 251) (mod i 241)) src))
      (is (= tried-before (bitcoin-lisp.networking::address-book-n-tried book))))))
