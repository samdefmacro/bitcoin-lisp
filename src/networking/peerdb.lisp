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
manager; these records are its entries."
  (ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
      :type (simple-array (unsigned-byte 8) (16)))
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
  ;; How many NEW buckets reference this entry (0 once it lives in TRIED).
  (ref-count 0 :type (unsigned-byte 8))
  ;; T when the entry lives in the TRIED table.
  (in-tried nil :type boolean)
  ;; Index into the address-book's random-id vector (for O(1) removal).
  (random-pos -1 :type fixnum)
  ;; Internal address-book id (key into the info map).
  (id 0 :type fixnum))

;;;; Address Book Key

(defun make-address-key (ip port)
  "Create an 18-byte key from IP (16 bytes) and PORT (2 bytes)."
  (let ((key (make-array 18 :element-type '(unsigned-byte 8))))
    (replace key ip)
    (setf (aref key 16) (ldb (byte 8 8) port))
    (setf (aref key 17) (ldb (byte 8 0) port))
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
  "Convert 16-byte IP address to a string.
IPv4-mapped addresses (::ffff:a.b.c.d) are rendered as dotted quad."
  (if (ipv4-mapped-p ip)
      ;; IPv4-mapped
      (format nil "~D.~D.~D.~D" (aref ip 12) (aref ip 13) (aref ip 14) (aref ip 15))
      ;; Full IPv6
      (format nil "~{~(~4,'0X~)~^:~}"
              (loop for i from 0 below 16 by 2
                    collect (logior (ash (aref ip i) 8) (aref ip (1+ i)))))))

(defun string-to-ip-bytes (addr-string)
  "Convert an IPv4 dotted-quad string to 16-byte IPv4-mapped IPv6."
  (let ((parts (mapcar #'parse-integer
                       (uiop:split-string addr-string :separator "."))))
    (when (= (length parts) 4)
      (apply #'ipv4-to-mapped-ipv6 parts))))
