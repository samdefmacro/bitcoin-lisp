(in-package #:bitcoin-lisp.networking)

;;; Persistent Peer Database
;;;
;;; Tracks known peer addresses with reputation scoring and persistence.
;;; Enables warm starts and informed peer selection.

;;;; Data Structures

(defstruct peer-address
  "A known peer address with reputation data."
  (ip (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
      :type (simple-array (unsigned-byte 8) (16)))
  (port 0 :type (unsigned-byte 16))
  (services 0 :type (unsigned-byte 64))
  (last-seen 0 :type (unsigned-byte 32))
  (last-attempt 0 :type (unsigned-byte 32))
  (successes 0 :type (unsigned-byte 16))
  (failures 0 :type (unsigned-byte 16)))

(defstruct address-book
  "In-memory address book of known peers."
  (entries (make-hash-table :test 'equalp) :type hash-table)
  (max-entries 2000 :type (unsigned-byte 16))
  (dirty nil :type boolean))

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

;;;; Peer Scoring

(defun compute-peer-score (peer-addr &optional (now (bitcoin-lisp.serialization:get-unix-time)))
  "Compute selection priority score: reliability / sqrt(age).
Reliability = successes / (successes + failures), defaulting to 0.5 for untried peers.
Age = max(1, hours since last-seen)."
  (let* ((s (peer-address-successes peer-addr))
         (f (peer-address-failures peer-addr))
         (reliability (if (zerop (+ s f))
                          0.5
                          (/ (float s) (float (+ s f)))))
         (age-seconds (max 1 (- now (peer-address-last-seen peer-addr))))
         (age-hours (max 1.0 (/ (float age-seconds) 3600.0))))
    (/ reliability (sqrt age-hours))))

;;;; Address Book Operations

(defun address-book-add (book peer-addr)
  "Add or update a peer address in the address book.
If the book is full, evict the lowest-scored entry."
  (let* ((key (make-address-key (peer-address-ip peer-addr)
                                 (peer-address-port peer-addr)))
         (entries (address-book-entries book))
         (existing (gethash key entries)))
    (if existing
        ;; Update existing entry
        (progn
          (setf (peer-address-services existing) (peer-address-services peer-addr))
          (when (> (peer-address-last-seen peer-addr) (peer-address-last-seen existing))
            (setf (peer-address-last-seen existing) (peer-address-last-seen peer-addr))))
        ;; New entry - evict if full
        (progn
          (when (>= (hash-table-count entries) (address-book-max-entries book))
            (address-book-evict-lowest book))
          (setf (gethash key entries) peer-addr)))
    (setf (address-book-dirty book) t)
    peer-addr))

(defun address-book-lookup (book ip port)
  "Look up a peer address by IP and PORT."
  (gethash (make-address-key ip port) (address-book-entries book)))

(defun address-book-evict-lowest (book)
  "Evict the entry with the lowest score."
  (let ((entries (address-book-entries book))
        (lowest-key nil)
        (lowest-score most-positive-single-float))
    (maphash (lambda (key addr)
               (let ((score (compute-peer-score addr)))
                 (when (< score lowest-score)
                   (setf lowest-score score)
                   (setf lowest-key key))))
             entries)
    (when lowest-key
      (remhash lowest-key entries))))

(defun address-book-count (book)
  "Return the number of entries in the address book."
  (hash-table-count (address-book-entries book)))

(defun address-book-sorted-peers (book)
  "Return all peer addresses sorted by score descending."
  (let ((peers '()))
    (maphash (lambda (key addr)
               (declare (ignore key))
               (push addr peers))
             (address-book-entries book))
    (sort peers #'> :key #'compute-peer-score)))

;;;; Connection Tracking

(defun address-book-record-success (book ip port)
  "Record a successful connection to IP:PORT."
  (let ((addr (address-book-lookup book ip port)))
    (when addr
      (setf (peer-address-successes addr)
            (min 65535 (1+ (peer-address-successes addr))))
      (setf (peer-address-last-seen addr)
            (bitcoin-lisp.serialization:get-unix-time))
      (setf (address-book-dirty book) t))))

(defun address-book-record-failure (book ip port)
  "Record a failed connection to IP:PORT."
  (let ((addr (address-book-lookup book ip port)))
    (when addr
      (setf (peer-address-failures addr)
            (min 65535 (1+ (peer-address-failures addr))))
      (setf (peer-address-last-attempt addr)
            (bitcoin-lisp.serialization:get-unix-time))
      (setf (address-book-dirty book) t))))

;;;; Persistence

(defparameter +peers-magic+ #(#x50 #x45 #x45 #x52)  ; "PEER"
  "Magic bytes for peers.dat file.")

(defconstant +peers-format-version+ 1)
(defconstant +peer-entry-size+ 38)

(defun save-address-book (book path)
  "Save the address book to PATH using atomic write."
  (ensure-directories-exist path)
  (let ((tmp-path (make-pathname :defaults path
                                 :type (concatenate 'string
                                                    (or (pathname-type path) "dat")
                                                    ".tmp"))))
    (let ((all-bytes
            (coerce
             (flexi-streams:with-output-to-sequence (stream)
               ;; Magic
               (write-sequence +peers-magic+ stream)
               ;; Version
               (bitcoin-lisp.serialization:write-uint32-le stream +peers-format-version+)
               ;; Entry count
               (bitcoin-lisp.serialization:write-uint32-le stream (hash-table-count (address-book-entries book)))
               ;; Entries
               (maphash (lambda (key addr)
                          (declare (ignore key))
                          ;; IP (16 bytes)
                          (write-sequence (peer-address-ip addr) stream)
                          ;; Port (2 bytes, big-endian)
                          (write-byte (ldb (byte 8 8) (peer-address-port addr)) stream)
                          (write-byte (ldb (byte 8 0) (peer-address-port addr)) stream)
                          ;; Services (8 bytes LE)
                          (bitcoin-lisp.serialization:write-uint64-le stream (peer-address-services addr))
                          ;; Last-seen (4 bytes LE)
                          (bitcoin-lisp.serialization:write-uint32-le stream (peer-address-last-seen addr))
                          ;; Last-attempt (4 bytes LE)
                          (bitcoin-lisp.serialization:write-uint32-le stream (peer-address-last-attempt addr))
                          ;; Successes (2 bytes LE)
                          (bitcoin-lisp.serialization:write-uint16-le stream (peer-address-successes addr))
                          ;; Failures (2 bytes LE)
                          (bitcoin-lisp.serialization:write-uint16-le stream (peer-address-failures addr)))
                        (address-book-entries book)))
             '(simple-array (unsigned-byte 8) (*)))))
      ;; Write data + CRC32 to temp file
      (with-open-file (out tmp-path
                           :direction :output
                           :if-exists :supersede
                           :element-type '(unsigned-byte 8))
        (write-sequence all-bytes out)
        (write-sequence (bitcoin-lisp.storage:compute-crc32 all-bytes) out)))
    ;; Atomic rename
    (rename-file tmp-path path))
  (setf (address-book-dirty book) nil)
  t)

(defun load-address-book (book path)
  "Load the address book from PATH with CRC32 verification.
Returns T if loaded, NIL if file missing or corrupted."
  (unless (probe-file path)
    (return-from load-address-book nil))
  (handler-case
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (let* ((file-size (file-length in))
               (data (make-array file-size :element-type '(unsigned-byte 8))))
          (read-sequence data in)
          ;; Verify minimum size: magic(4) + version(4) + count(4) + crc32(4)
          (when (< file-size 16)
            (bitcoin-lisp:log-warn "peers.dat too small, ignoring")
            (return-from load-address-book nil))
          ;; Verify CRC32
          (let ((payload (subseq data 0 (- file-size 4)))
                (stored-crc (subseq data (- file-size 4))))
            (unless (equalp (bitcoin-lisp.storage:compute-crc32 payload) stored-crc)
              (bitcoin-lisp:log-warn "peers.dat CRC32 mismatch, ignoring")
              (return-from load-address-book nil))
            ;; Parse
            (flexi-streams:with-input-from-sequence (stream payload)
              ;; Magic
              (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
                (read-sequence magic stream)
                (unless (equalp magic +peers-magic+)
                  (bitcoin-lisp:log-warn "peers.dat bad magic, ignoring")
                  (return-from load-address-book nil)))
              ;; Version
              (let ((version (bitcoin-lisp.serialization:read-uint32-le stream)))
                (unless (= version +peers-format-version+)
                  (bitcoin-lisp:log-warn "peers.dat unsupported version ~D" version)
                  (return-from load-address-book nil)))
              ;; Entry count
              (let ((count (bitcoin-lisp.serialization:read-uint32-le stream)))
                ;; Read entries
                (dotimes (i count)
                  (let* ((ip (make-array 16 :element-type '(unsigned-byte 8))))
                    (read-sequence ip stream)
                    (let* ((port-high (read-byte stream))
                           (port-low (read-byte stream))
                           (port (logior (ash port-high 8) port-low))
                           (services (bitcoin-lisp.serialization:read-uint64-le stream))
                           (last-seen (bitcoin-lisp.serialization:read-uint32-le stream))
                           (last-attempt (bitcoin-lisp.serialization:read-uint32-le stream))
                           (successes (bitcoin-lisp.serialization:read-uint16-le stream))
                           (failures (bitcoin-lisp.serialization:read-uint16-le stream))
                           (addr (make-peer-address
                                  :ip ip :port port :services services
                                  :last-seen last-seen :last-attempt last-attempt
                                  :successes successes :failures failures)))
                      (setf (gethash (make-address-key ip port)
                                     (address-book-entries book))
                            addr))))
                (bitcoin-lisp:log-info "Loaded ~D peer addresses from peers.dat" count)
                t)))))
    (error (c)
      (bitcoin-lisp:log-warn "Failed to load peers.dat: ~A" c)
      nil)))

(defun peers-dat-path (data-directory)
  "Return the path to peers.dat in DATA-DIRECTORY."
  (merge-pathnames "peers.dat" data-directory))

;;;; IP String Conversion

(defun ip-bytes-to-string (ip)
  "Convert 16-byte IP address to a string.
IPv4-mapped addresses (::ffff:a.b.c.d) are rendered as dotted quad."
  (if (and (= (aref ip 10) #xFF) (= (aref ip 11) #xFF)
           (every #'zerop (subseq ip 0 10)))
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
