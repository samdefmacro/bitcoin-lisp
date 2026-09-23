(in-package #:bitcoin-lisp.networking)

;;;; peers.dat in Bitcoin Core's format (addrdb.cpp, AddrManImpl::Serialize /
;;;; Unserialize / CheckAddrman in addrman.cpp)
;;;;
;;;; The file is Core's SerializeDB: the chain's message-start bytes, the
;;;; serialized AddrMan, and a SHA256d over everything before it. The AddrMan
;;;; part stores no bucket POSITIONS, only which new-table buckets name which
;;;; entry: positions are re-derived from the secret key on load, which is why
;;;; a reader can re-bucket (a changed -asmap) without the writer's help.
;;;;
;;;; Before this, peers.dat was a format of our own (magic "ADRM", CRC32).
;;;; LOAD-ADDRESS-BOOK still READS that one for one transition, so a node
;;;; upgraded in place keeps its address book; it is rewritten in Core's format
;;;; at once and never written in the old one again.

(defconstant +addrman-file-format+ 4
  "Core AddrManImpl::FILE_FORMAT = Format::V4_MULTIPORT (addrman_impl.h:166-179):
the format written, and the highest this reader understands.")

(defconstant +addrman-incompatibility-base+ 32
  "Core INCOMPATIBILITY_BASE (addrman_impl.h:181): added to the lowest
compatible format in the file's second byte, so a pre-versioning reader sees a
value it refuses.")

(defconstant +addrman-format-v1-deterministic+ 1)
(defconstant +addrman-format-v2-asmap+ 2)
(defconstant +addrman-format-v3-bip155+ 3)

(defconstant +caddress-disk-version-addrv2+ (ash 1 29)
  "Core CAddress::DISK_VERSION_ADDRV2 (protocol.h:391).")

(defconstant +caddress-disk-version-init+ 220000
  "Core CAddress::DISK_VERSION_INIT (protocol.h:386): the low bits of a disk
CAddress's version field, written and ignored.")

(defconstant +caddress-disk-version-ignore-mask+ #x7FFFF
  "Core CAddress::DISK_VERSION_IGNORE_MASK (protocol.h:387).")

(defconstant +max-addrv2-size+ 512
  "Core CNetAddr::MAX_ADDRV2_SIZE (netaddress.h:283).")

(defvar *addrman-check-ratio* 0
  "Core -checkaddrman (addrman.h:32, init.cpp:643): run CHECK-ADDRESS-BOOK on
one in N address-book operations; 0 never.")

;;;; Read errors, in Core's words

(define-condition addrdb-read-error (error)
  ((message :initarg :message :reader addrdb-read-error-message)
   (ios :initarg :ios :initform nil :reader addrdb-read-error-ios-p))
  (:report (lambda (c s)
             ;; A std::ios_base::failure's what() is the message followed by
             ;; libstdc++'s ": iostream error"; a std::runtime_error's is the
             ;; message alone. feature_addrman.py matches both shapes.
             (format s "~A~:[~;: iostream error~]"
                     (addrdb-read-error-message c)
                     (addrdb-read-error-ios-p c))))
  (:documentation "A peers.dat that cannot be read: the exception Core's
DeserializeDB lets escape to LoadAddrman (addrdb.cpp:101-124). IOS is T for a
std::ios_base::failure and NIL for a std::runtime_error."))

(define-condition addrman-version-error (addrdb-read-error) ()
  (:documentation "Core InvalidAddrManVersionError (addrman.h:28): a file
written by a newer format this reader must not parse. LoadAddrman backs it up
and starts afresh instead of refusing to start."))

(defun %addrdb-fail (ios control &rest args)
  (error 'addrdb-read-error :message (apply #'format nil control args) :ios ios))

;;;; A bounds-checked reader over the file's bytes

(defstruct (%addrdb-reader (:constructor %make-addrdb-reader (data)))
  (data #() :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum))

(defun %rd-bytes (rd n)
  (let* ((data (%addrdb-reader-data rd))
         (pos (%addrdb-reader-pos rd))
         (end (+ pos n)))
    (when (> end (length data))
      ;; AutoFile::read (streams.cpp:30-33).
      (%addrdb-fail t "AutoFile::read: end of file"))
    (setf (%addrdb-reader-pos rd) end)
    (subseq data pos end)))

(defun %rd-uint (rd n)
  "An N-byte little-endian unsigned integer."
  (let ((b (%rd-bytes rd n)))
    (loop for i below n sum (ash (aref b i) (* 8 i)))))

(defun %rd-int (rd n)
  "An N-byte little-endian two's-complement integer."
  (let ((u (%rd-uint rd n)))
    (if (logbitp (1- (* 8 n)) u) (- u (ash 1 (* 8 n))) u)))

(defun %rd-compact-size (rd &key (range-check t))
  "Core ReadCompactSize (serialize.h:330-360)."
  (let* ((first (%rd-uint rd 1))
         (value (cond ((< first 253) first)
                      ((= first 253)
                       (let ((v (%rd-uint rd 2)))
                         (when (< v 253) (%addrdb-fail t "non-canonical ReadCompactSize()"))
                         v))
                      ((= first 254)
                       (let ((v (%rd-uint rd 4)))
                         (when (< v #x10000) (%addrdb-fail t "non-canonical ReadCompactSize()"))
                         v))
                      (t
                       (let ((v (%rd-uint rd 8)))
                         (when (< v #x100000000) (%addrdb-fail t "non-canonical ReadCompactSize()"))
                         v)))))
    (when (and range-check (> value #x02000000))
      (%addrdb-fail t "ReadCompactSize(): size too large"))
    value))

;;;; CNetAddr / CService / CAddress / AddrInfo codecs

(defun %bip155-length (net)
  (ecase net (:ipv4 4) (:ipv6 16) (:torv3 32) (:i2p 32) (:cjdns 16)))

(defun %bip155-name (net)
  "The network names Core's length error uses (netaddress.cpp:185-190)."
  (ecase net (:ipv4 "IPv4") (:ipv6 "IPv6") (:torv3 "TORv3") (:i2p "I2P")
    (:cjdns "CJDNS")))

(defun %ipv6-embeds-other-network-p (ip)
  "T for a 16-byte IPv6 address that is really another network's encoding --
IPv4-mapped, a TORv2 carrier, or Core's internal prefix -- which Core refuses
as a V2 IPv6 address (netaddress.cpp:210-221) or reads as NET_INTERNAL, which
this address book does not keep."
  (or (ipv4-mapped-p ip)
      (%ipv6-prefix-p ip '(#xFD #x87 #xD8 #x7E #xEB #x43))
      (%ipv6-prefix-p ip '(#xFD #x6B #x88 #xC0 #x87 #x24))))

(defun %write-netaddr-v2 (bb net ip)
  "CNetAddr::SerializeV2Stream (netaddress.h:326-352): BIP155 network id, a
CompactSize length and the address bytes -- 4 of them for IPv4, which this
book keeps in the 16-byte mapped form."
  (let ((bytes (if (eq net :ipv4) (subseq ip 12 16) ip)))
    (bl.bytes:bb-write-u8 bb (network-key-id net))
    (bl.bytes:bb-write-varint bb (length bytes))
    (bl.bytes:bb-write-bytes bb bytes)))

(defun %read-netaddr-v2 (rd)
  "CNetAddr::UnserializeV2Stream (netaddress.h:385-420). Returns (values NET
IP), IP 16 bytes for IPv4/IPv6/CJDNS and 32 for TORv3/I2P, or NIL for an
address this book cannot hold (an unknown network, an embedded encoding, an
unspecified address) -- Core reads such an address as invalid and its entry
is dropped on load rather than failing the file."
  (let* ((id (%rd-uint rd 1))
         (len (%rd-compact-size rd :range-check nil)))
    (when (> len +max-addrv2-size+)
      (%addrdb-fail t "Address too long: ~D > ~D" len +max-addrv2-size+))
    (let ((net (key-id-network id))
          (bytes (%rd-bytes rd len)))
      (when (and net (/= len (%bip155-length net)))
        (%addrdb-fail t "BIP155 ~A address with length ~D (should be ~D)"
                      (%bip155-name net) len (%bip155-length net)))
      (case net
        ((nil) nil)
        (:ipv4 (values net (ipv4-to-mapped-ipv6 (aref bytes 0) (aref bytes 1)
                                                (aref bytes 2) (aref bytes 3))))
        (:ipv6 (unless (%ipv6-embeds-other-network-p bytes) (values net bytes)))
        (t (values net bytes))))))

(defun %read-netaddr-v1 (rd)
  "CNetAddr::UnserializeV1Array (netaddress.h:370-380): 16 bytes, IPv4 in its
mapped form. Returns (values NET IP) or NIL as %READ-NETADDR-V2 does."
  (let ((ip (%rd-bytes rd 16)))
    (cond ((ipv4-mapped-p ip) (values :ipv4 ip))
          ((%ipv6-embeds-other-network-p ip) nil)
          (t (values :ipv6 ip)))))

(defun %addrinfo-valid-p (net ip)
  "Core CNetAddr::IsValid (netaddress.cpp:437-470) for what this reader can
produce: a known network, not the unspecified address, not INADDR_NONE, not
RFC3849 documentation space."
  (and net ip
       (notevery #'zerop (if (eq net :ipv4) (subseq ip 12 16) ip))
       (not (and (eq net :ipv4) (every (lambda (b) (= b 255)) (subseq ip 12 16))))
       (not (and (eq net :ipv6) (%ipv6-prefix-p ip '(#x20 #x01 #x0D #xB8))))))

(defun %write-caddress-disk (bb pa)
  "A CAddress in Core's V2_DISK form (protocol.h:413-454): the disk version
220000|2^29, nTime, CompactSize services, the BIP155 CNetAddr and a big-endian
port."
  (bl.bytes:bb-write-u32-le bb (logior +caddress-disk-version-init+
                                       +caddress-disk-version-addrv2+))
  (bl.bytes:bb-write-u32-le bb (peer-address-last-seen pa))
  (bl.bytes:bb-write-varint bb (peer-address-services pa))
  (%write-netaddr-v2 bb (peer-address-network pa) (peer-address-ip pa))
  (bl.bytes:bb-write-u8 bb (ldb (byte 8 8) (peer-address-port pa)))
  (bl.bytes:bb-write-u8 bb (ldb (byte 8 0) (peer-address-port pa))))

(defun %write-addrinfo (bb pa)
  "AddrInfo (addrman_impl.h:73-76): the disk CAddress, then the source
CNetAddr, m_last_success as int64 and nAttempts as int32. m_last_try is not
part of it, in Core or here."
  (let ((source (peer-address-source pa)))
    (%write-caddress-disk bb pa)
    ;; An entry with no recorded source (one the address book learned before
    ;; sources were kept, or one we added ourselves) names itself, which is
    ;; what Core's own self-sourced adds store (rpc/net.cpp addpeeraddress).
    (if source
        (%write-netaddr-v2 bb (car source) (cdr source))
        (%write-netaddr-v2 bb (peer-address-network pa) (peer-address-ip pa)))
    (bl.bytes:bb-write-i64-le bb (peer-address-last-success pa))
    (bl.bytes:bb-write-i32-le bb (min (peer-address-n-attempts pa) #x7FFFFFFF))))

(defun %read-caddress-disk (rd v2-stream)
  "Read one disk CAddress. Returns (values NET IP PORT SERVICES TIME); NET and
IP are NIL for an address this book cannot hold. V2-STREAM is Core's
ser_params: whether ADDRv2 is permitted at all."
  (let* ((version (%rd-uint rd 4))
         (stored (logandc2 version +caddress-disk-version-ignore-mask+))
         (use-v2 (cond ((zerop stored) nil)
                       ((and (= stored +caddress-disk-version-addrv2+) v2-stream) t)
                       (t (%addrdb-fail t "Unsupported CAddress disk format version"))))
         (time (%rd-uint rd 4))
         (services (if use-v2
                       (%rd-compact-size rd :range-check nil)
                       (%rd-uint rd 8))))
    (multiple-value-bind (net ip) (if use-v2 (%read-netaddr-v2 rd) (%read-netaddr-v1 rd))
      (let ((port (let ((b (%rd-bytes rd 2))) (logior (ash (aref b 0) 8) (aref b 1)))))
        (values net ip port (ldb (byte 64 0) services) time)))))

(defun %read-addrinfo (rd v2-stream)
  "Read one AddrInfo. Returns a fresh PEER-ADDRESS carrying the entry's fields
(not yet in any book), or NIL for an invalid address, which Core reads and
then drops (addrman.cpp:291-312, 359)."
  (multiple-value-bind (net ip port services time) (%read-caddress-disk rd v2-stream)
    (multiple-value-bind (snet sip)
        (if v2-stream (%read-netaddr-v2 rd) (%read-netaddr-v1 rd))
      (let ((last-success (%rd-int rd 8))
            (attempts (%rd-int rd 4)))
        (when (%addrinfo-valid-p net ip)
          (make-peer-address
           :net net :ip ip :port port :services services :last-seen time
           :last-success (max 0 (min last-success #xFFFFFFFF))
           :n-attempts (max 0 attempts)
           :source (when (%addrinfo-valid-p snet sip) (cons snet sip))))))))

;;;; CheckAddrman

(defun %address-book-check-code (book)
  "Core AddrManImpl::CheckAddrman (addrman.cpp:1063-1150) over this book: 0
when every index agrees with every other, else Core's negative code for the
first disagreement, in Core's order. The per-network counts (-20/-21) have no
counterpart here."
  (let* ((info (address-book-info book))
         (random-ids (address-book-random-ids book))
         (n-new (address-book-n-new book))
         (n-tried (address-book-n-tried book))
         (set-tried (make-hash-table))
         (map-new (make-hash-table)))
    (unless (= (fill-pointer random-ids) (+ n-tried n-new))
      (return-from %address-book-check-code -7))
    (maphash
     (lambda (id pa)
       (if (peer-address-in-tried pa)
           (progn
             (when (zerop (peer-address-last-success pa))
               (return-from %address-book-check-code -1))
             (when (plusp (peer-address-ref-count pa))
               (return-from %address-book-check-code -2))
             (setf (gethash id set-tried) t))
           (progn
             (when (> (peer-address-ref-count pa) +addrman-new-buckets-per-address+)
               (return-from %address-book-check-code -3))
             (when (zerop (peer-address-ref-count pa))
               (return-from %address-book-check-code -4))
             (setf (gethash id map-new) (peer-address-ref-count pa))))
       (unless (eql id (gethash (peer-address-key pa) (address-book-addr-map book)))
         (return-from %address-book-check-code -5))
       (let ((pos (peer-address-random-pos pa)))
         (unless (and (<= 0 pos) (< pos (fill-pointer random-ids))
                      (eql id (aref random-ids pos)))
           (return-from %address-book-check-code -14))))
     info)
    (unless (= (hash-table-count set-tried) n-tried)
      (return-from %address-book-check-code -9))
    (unless (= (hash-table-count map-new) n-new)
      (return-from %address-book-check-code -10))
    (let ((tt (address-book-tried-table book)))
      (dotimes (b +addrman-tried-bucket-count+)
        (dotimes (i +addrman-bucket-size+)
          (let ((id (aref tt (bucket-slot b i))))
            (when (/= id -1)
              (unless (gethash id set-tried)
                (return-from %address-book-check-code -11))
              (let ((pa (gethash id info)))
                (unless (and pa (= (tried-bucket book pa) b))
                  (return-from %address-book-check-code -17))
                (unless (= (bucket-position book pa nil b) i)
                  (return-from %address-book-check-code -18)))
              (remhash id set-tried))))))
    (let ((nt (address-book-new-table book)))
      (dotimes (b +addrman-new-bucket-count+)
        (dotimes (i +addrman-bucket-size+)
          (let ((id (aref nt (bucket-slot b i))))
            (when (/= id -1)
              (unless (gethash id map-new)
                (return-from %address-book-check-code -12))
              (let ((pa (gethash id info)))
                (unless (and pa (= (bucket-position book pa t b) i))
                  (return-from %address-book-check-code -19)))
              (when (zerop (decf (gethash id map-new)))
                (remhash id map-new)))))))
    (cond ((plusp (hash-table-count set-tried)) -13)
          ((plusp (hash-table-count map-new)) -15)
          ((every #'zerop (address-book-key book)) -16)
          (t 0))))

(defun check-address-book (book)
  "Core CheckAddrman with its timer lines (LOG_TIME_MILLIS_WITH_CATEGORY_MSG_ONCE,
addrman.cpp:1067-1068; logging/timer.h): `CheckAddrman: new N, tried N, total N
started' and `CheckAddrman: completed (Xms)' under -debug=addrman. Returns the
check code, 0 when consistent."
  (bl.log:log-cat "addrman" "CheckAddrman: new ~D, tried ~D, total ~D started"
                  (address-book-n-new book) (address-book-n-tried book)
                  (fill-pointer (address-book-random-ids book)))
  (let* ((start (get-internal-real-time))
         (code (%address-book-check-code book)))
    (bl.log:log-cat "addrman" "CheckAddrman: completed (~,2Fms)"
                    (/ (* 1000.0d0 (- (get-internal-real-time) start))
                       internal-time-units-per-second))
    code))

(defun maybe-check-address-book (book)
  "Core AddrManImpl::Check (addrman.cpp:1048-1061), run on entry to the address
book's operations: one in *ADDRMAN-CHECK-RATIO* of them runs the full check,
and a failure is fatal -- Core logs it and asserts."
  (let ((ratio *addrman-check-ratio*))
    (when (and (plusp ratio) (< (random ratio) 1))
      (let ((code (check-address-book book)))
        (unless (zerop code)
          (bl.log:log-error "ADDRMAN CONSISTENCY CHECK FAILED!!! err=~D" code)
          (internal-error "ADDRMAN CONSISTENCY CHECK FAILED!!! err=~D" code))))))

;;;; Serialize

(defun %asmap-version-bytes ()
  "Core NetGroupManager::GetAsmapVersion as it is serialized: SHA256d of the
loaded -asmap, or 32 zero bytes without one (netgroup.cpp:13-17)."
  (if (and *asmap* (plusp (length *asmap*)))
      (bl.crypto:hash256 *asmap*)
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun serialize-address-book (book)
  "BOOK as Core's AddrManImpl::Serialize writes it (addrman.cpp:133-229): the
format byte, INCOMPATIBILITY_BASE + V4_MULTIPORT, nKey, nNew, nTried, the new
bucket count XOR 2^30, every new entry, every tried entry, then per new bucket
its occupancy and the index of each occupant among the new entries, and the
asmap version. Entries go out in id order so the bytes are reproducible."
  (let* ((entries (sort (loop for pa being the hash-values of (address-book-info book)
                              collect pa)
                        #'< :key #'peer-address-id))
         (new (remove-if (lambda (pa) (or (peer-address-in-tried pa)
                                          (zerop (peer-address-ref-count pa))))
                         entries))
         (tried (remove-if-not #'peer-address-in-tried entries))
         (index (make-hash-table))
         (nt (address-book-new-table book)))
    (loop for pa in new for n from 0
          do (setf (gethash (peer-address-id pa) index) n))
    (bl.bytes:with-byte-buf (bb)
      (bl.bytes:bb-write-u8 bb +addrman-file-format+)
      (bl.bytes:bb-write-u8 bb (+ +addrman-incompatibility-base+ +addrman-file-format+))
      (bl.bytes:bb-write-bytes bb (address-book-key book))
      (bl.bytes:bb-write-i32-le bb (length new))
      (bl.bytes:bb-write-i32-le bb (length tried))
      (bl.bytes:bb-write-i32-le bb (logxor +addrman-new-bucket-count+ (ash 1 30)))
      (dolist (pa new) (%write-addrinfo bb pa))
      (dolist (pa tried) (%write-addrinfo bb pa))
      (dotimes (b +addrman-new-bucket-count+)
        (let ((ids (loop for i below +addrman-bucket-size+
                         for id = (aref nt (bucket-slot b i))
                         when (gethash id index) collect (gethash id index))))
          (bl.bytes:bb-write-i32-le bb (length ids))
          (dolist (n ids) (bl.bytes:bb-write-i32-le bb n))))
      (bl.bytes:bb-write-bytes bb (%asmap-version-bytes)))))

;;;; Unserialize

(defun %place-new-entry (book pa bucket)
  "Put PA in new BUCKET at its position; T when the slot was free."
  (let* ((pos (bucket-position book pa t bucket))
         (slot (bucket-slot bucket pos))
         (nt (address-book-new-table book)))
    (when (= (aref nt slot) -1)
      (setf (aref nt slot) (peer-address-id pa))
      (incf (peer-address-ref-count pa))
      t)))

(defun %register-entry (book pa)
  "Give the fresh record PA the next id and enter it in BOOK's maps."
  (let ((id (address-book-next-id book)))
    (incf (address-book-next-id book))
    (setf (peer-address-id pa) id
          (peer-address-source-group pa)
          (let ((source (peer-address-source pa)))
            (if source
                (net-group-key (cdr source) (car source))
                (peer-address-group pa)))
          (gethash id (address-book-info book)) pa
          (gethash (peer-address-key pa) (address-book-addr-map book)) id)
    (ab-random-push book pa)
    pa))

(defun %unserialize-new-and-tried (rd book v2-stream n-new n-tried)
  "Read N-NEW new entries (returned as a vector indexed as in the file, NIL for
an invalid one) and N-TRIED tried entries, placing each tried entry at its
position unless the slot is taken (Core addrman.cpp:285-312). Returns the
vector and the number of tried entries lost."
  (let ((new (make-array n-new :initial-element nil))
        (lost 0))
    (dotimes (n n-new)
      (let ((pa (%read-addrinfo rd v2-stream)))
        (when pa
          (%register-entry book pa)
          (incf (address-book-n-new book))
          (setf (aref new n) pa))))
    (dotimes (n n-tried)
      (let ((pa (%read-addrinfo rd v2-stream)))
        (if (null pa)
            (incf lost)
            (let* ((tb (tried-bucket book pa))
                   (slot (bucket-slot tb (bucket-position book pa nil tb)))
                   (tt (address-book-tried-table book)))
              (if (/= (aref tt slot) -1)
                  (incf lost)
                  (progn
                    (%register-entry book pa)
                    (setf (peer-address-in-tried pa) t
                          (aref tt slot) (peer-address-id pa))
                    (incf (address-book-n-tried book))))))))
    (values new lost)))

(defun unserialize-address-book (rd book)
  "Core AddrManImpl::Unserialize (addrman.cpp:231-399) from reader RD into the
empty BOOK, with its errors worded as Core's."
  (let* ((format (%rd-uint rd 1))
         (v2-stream (>= format +addrman-format-v3-bip155+))
         (compat (%rd-uint rd 1)))
    (when (< compat +addrman-incompatibility-base+)
      (%addrdb-fail t "Corrupted addrman database: The compat value (~D) is lower than the expected minimum value ~D."
                    compat +addrman-incompatibility-base+))
    (let ((lowest (- compat +addrman-incompatibility-base+)))
      (when (> lowest +addrman-file-format+)
        (error 'addrman-version-error
               :ios t
               :message (format nil "Unsupported format of addrman database: ~D. It is compatible with formats >=~D, but the maximum supported by this version of ~A is ~D."
                                format lowest "bitcoin-lisp" +addrman-file-format+))))
    (replace (address-book-key book) (%rd-bytes rd 32))
    (let* ((n-new (%rd-int rd 4))
           (n-tried (%rd-int rd 4))
           (n-ubuckets (let ((v (%rd-int rd 4)))
                         (if (>= format +addrman-format-v1-deterministic+)
                             (logxor v (ash 1 30))
                             v)))
           (max-new (* +addrman-new-bucket-count+ +addrman-bucket-size+))
           (max-tried (* +addrman-tried-bucket-count+ +addrman-bucket-size+)))
      (unless (<= 0 n-new max-new)
        (%addrdb-fail t "Corrupt AddrMan serialization: nNew=~D, should be in [0, ~D]"
                      n-new max-new))
      (unless (<= 0 n-tried max-tried)
        (%addrdb-fail t "Corrupt AddrMan serialization: nTried=~D, should be in [0, ~D]"
                      n-tried max-tried))
      (multiple-value-bind (new lost)
          (%unserialize-new-and-tried rd book v2-stream n-new n-tried)
        (let ((bucket-entries
                (loop for bucket below (max 0 n-ubuckets)
                      nconc (loop repeat (%rd-int rd 4)
                                  for n = (%rd-int rd 4)
                                  when (< -1 n n-new) collect (cons bucket n))))
              (serialized-version
                (if (>= format +addrman-format-v2-asmap+)
                    (%rd-bytes rd 32)
                    (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
          (let ((restore (and (= n-ubuckets +addrman-new-bucket-count+)
                              (equalp serialized-version (%asmap-version-bytes)))))
            (unless restore
              (bl.log:log-cat "addrman" "Bucketing method was updated, re-bucketing addrman entries from disk"))
            (loop for (bucket . n) in bucket-entries
                  for pa = (aref new n)
                  when (and pa (< (peer-address-ref-count pa)
                                  +addrman-new-buckets-per-address+))
                    do (unless (and restore (%place-new-entry book pa bucket))
                         (%place-new-entry
                          book pa (new-bucket book pa (peer-address-source-group pa))))))
          ;; Prune new entries no bucket took (addrman.cpp:376-387).
          (let ((lost-new 0))
            (loop for pa across new
                  when (and pa (zerop (peer-address-ref-count pa)))
                    do (ab-delete book (peer-address-id pa))
                       (incf lost-new))
            (when (plusp (+ lost lost-new))
              (bl.log:log-cat "addrman" "addrman lost ~D new and ~D tried addresses due to collisions or invalid addresses"
                              lost-new lost))))))
    (let ((code (check-address-book book)))
      (unless (zerop code)
        (%addrdb-fail t "Corrupt data. Consistency check failed with code ~D" code)))
    book))

;;;; The file (SerializeDB / DeserializeDB)

(defun encode-peers-dat (book network)
  "The whole peers.dat for BOOK on NETWORK: message start, AddrMan, SHA256d of
both (addrdb.cpp:38-50)."
  (let* ((body (concatenate '(simple-array (unsigned-byte 8) (*))
                            (bl.chain:network-magic network)
                            (serialize-address-book book))))
    (concatenate '(simple-array (unsigned-byte 8) (*)) body (bl.crypto:hash256 body))))

(defun decode-peers-dat (bytes book network)
  "Core DeserializeDB (addrdb.cpp:101-124) over the file's BYTES into the empty
BOOK: the network's message start, the AddrMan, and the checksum over what was
read."
  (let ((rd (%make-addrdb-reader bytes)))
    (unless (equalp (%rd-bytes rd 4) (bl.chain:network-magic network))
      (%addrdb-fail nil "Invalid network magic number"))
    (unserialize-address-book rd book)
    (let* ((consumed (%addrdb-reader-pos rd))
           (expected (bl.crypto:hash256 (subseq bytes 0 consumed))))
      (unless (equalp (%rd-bytes rd 32) expected)
        (%addrdb-fail nil "Checksum mismatch, data corrupted")))
    book))

;;;; The format this node wrote before (read for one transition, never written)

(alexandria:define-constant +addrman-magic+ #(#x41 #x44 #x52 #x4D)  ; "ADRM"
  :test #'equalp
  :documentation "Magic of the peers.dat format this node wrote before it wrote
Core's: \"ADRM\", a uint32 version (2, 3 or 4), the bucket key, the counts,
the entries and a CRC32. Read only, so an upgraded node keeps its address
book; see %LOAD-LEGACY-PEERS-DAT.")

(defun %new-table-buckets (book)
  "Map id -> list of new-bucket numbers currently referencing it (one scan
over the new table; an address added from several source groups appears in
up to +addrman-new-buckets-per-address+ buckets)."
  (let ((m (make-hash-table))
        (nt (address-book-new-table book)))
    (dotimes (slot (length nt))
      (let ((id (aref nt slot)))
        (when (>= id 0)
          (push (floor slot +addrman-bucket-size+) (gethash id m)))))
    m))

(defun %legacy-load-entry (book tried-p net ip port services last-seen last-attempt
                           last-success n-attempts source-group new-buckets)
  "Reconstruct one entry of the old format into BOOK, preserving its stats and
its saved new-bucket numbers (v3+; v2 uses the bucket its source group
implies). A tried entry with no recorded success takes its last-seen time as
one: tried means we once connected, and Core's consistency check (-1) refuses
a tried entry without it."
  (let ((pa (ab-create book ip port services last-seen
                       (if (plusp (length source-group)) source-group nil)
                       net)))
    (incf (address-book-n-new book))
    (setf (peer-address-last-attempt pa) last-attempt
          (peer-address-last-success pa) (if (and tried-p (zerop last-success))
                                             (max 1 last-seen)
                                             last-success)
          (peer-address-n-attempts pa) n-attempts)
    (let ((buckets (or (remove-duplicates new-buckets)
                       (list (new-bucket book pa
                                         (or (peer-address-source-group pa)
                                             (peer-address-group pa)))))))
      (setf (peer-address-ref-count pa) 0)
      (dolist (b buckets)
        (let ((p (bucket-position book pa t b)))
          (ab-clear-new book b p)
          (incf (peer-address-ref-count pa))
          (setf (aref (address-book-new-table book) (bucket-slot b p))
                (peer-address-id pa)))))
    (when tried-p (ab-make-tried book pa))))

(defun %decode-legacy-peers-dat (data book)
  "Read the old format's DATA (whole file, CRC32 last) into BOOK. Returns the
entry count, or signals an ADDRDB-READ-ERROR."
  (let ((file-size (length data)))
    (when (< file-size 48)
      (%addrdb-fail nil "legacy peers.dat is too short"))
    (let ((payload (subseq data 0 (- file-size 4))))
      (unless (equalp (bl.kv:compute-crc32 payload) (subseq data (- file-size 4)))
        (%addrdb-fail nil "legacy peers.dat CRC32 mismatch"))
      (let* ((rd (%make-addrdb-reader payload))
             (magic (%rd-bytes rd 4))
             (version (%rd-uint rd 4)))
        (declare (ignore magic))
        (unless (member version '(2 3 4))
          (%addrdb-fail nil "legacy peers.dat version ~D unsupported" version))
        (replace (address-book-key book) (%rd-bytes rd 32))
        (%rd-uint rd 4)                 ; n-new (recomputed)
        (%rd-uint rd 4)                 ; n-tried (recomputed)
        (let ((count (%rd-uint rd 4)))
          (dotimes (i count count)
            (let* ((tried-p (= 1 (%rd-uint rd 1)))
                   ;; v4: net-id + length-prefixed address; v2/v3: a fixed
                   ;; 16-byte IP whose network is derived from the mapped form.
                   (net (when (>= version 4)
                          (or (key-id-network (%rd-uint rd 1))
                              (%addrdb-fail nil "legacy peers.dat: unknown network id"))))
                   (ip (%rd-bytes rd (if (>= version 4) (%rd-uint rd 1) 16)))
                   (port (let ((b (%rd-bytes rd 2))) (logior (ash (aref b 0) 8) (aref b 1))))
                   (services (%rd-uint rd 8))
                   (last-seen (%rd-uint rd 4))
                   (last-attempt (%rd-uint rd 4))
                   (last-success (%rd-uint rd 4))
                   (n-attempts (%rd-uint rd 4))
                   (sg (%rd-bytes rd (%rd-uint rd 1)))
                   (new-buckets (when (>= version 3)
                                  (loop repeat (%rd-uint rd 1)
                                        collect (%rd-uint rd 2)))))
              (%legacy-load-entry book tried-p net ip port services last-seen
                                  last-attempt last-success n-attempts sg
                                  new-buckets))))))))

;;;; LoadAddrman / DumpPeerAddresses

(defun %adopt-address-book (target source)
  "Make TARGET hold exactly what SOURCE holds (a load decodes into a fresh book
so a failure leaves nothing half-read behind, as Core resets its AddrMan)."
  (setf (address-book-next-id target) (address-book-next-id source)
        (address-book-info target) (address-book-info source)
        (address-book-addr-map target) (address-book-addr-map source)
        (address-book-random-ids target) (address-book-random-ids source)
        (address-book-new-table target) (address-book-new-table source)
        (address-book-tried-table target) (address-book-tried-table source)
        (address-book-n-new target) (address-book-n-new source)
        (address-book-n-tried target) (address-book-n-tried source)
        (address-book-tried-collisions target) (address-book-tried-collisions source)
        (address-book-last-good target) (address-book-last-good source)
        (address-book-dirty target) nil)
  (replace (address-book-key target) (address-book-key source))
  target)

(defun %peers-dat-sibling (path suffix)
  "PATH's namestring with SUFFIX appended (peers.dat.bak): built on the
namestring, since a dot inside a pathname TYPE is escaped."
  (concatenate 'string (namestring path) suffix))

(defun write-db-file (path bytes)
  "Core SerializeFileDB's commit (addrdb.cpp:55-98): BYTES to a temporary file
beside PATH, flushed to disk, then renamed over PATH, and the rename made
durable."
  (ensure-directories-exist path)
  (let ((tmp (%peers-dat-sibling path ".new")))
    (with-open-file (out tmp :direction :output :if-exists :supersede
                             :element-type '(unsigned-byte 8))
      (write-sequence bytes out)
      (finish-output out))
    (bl.kv:fsync-file tmp)
    (bl.kv:rename-path tmp path)
    (bl.kv:fsync-parent-directory path))
  t)

(defun save-address-book (book path &optional (network bl.chain:*network*))
  "Core DumpPeerAddresses (addrdb.cpp:191-195, SerializeFileDB :55-98): write
BOOK to PATH in Core's peers.dat format for NETWORK -- to a temporary file,
committed to disk, then renamed over PATH."
  (write-db-file path (encode-peers-dat book network))
  (setf (address-book-dirty book) nil)
  t)

(defun %load-legacy-peers-dat (book path data network)
  "The one-transition reader: a peers.dat in this node's former format loads,
is rewritten in Core's format at once, and says so once. A corrupt one is
backed up to peers.dat.bak and the book starts empty, as that format always
did."
  (let ((fresh (make-address-book)))
    (handler-case
        (let ((count (%decode-legacy-peers-dat data fresh)))
          (%adopt-address-book book fresh)
          (bl.log:log-info "Loaded ~D addresses from peers.dat" (address-book-count book))
          (save-address-book book path network)
          (bl.log:log-info "peers.dat migrated from bitcoin-lisp's own format to Bitcoin Core's (~D of ~D entries kept)"
                           (address-book-count book) count)
          (plusp count))
      (error (c)
        (bl.log:log-warn "Failed to load peers.dat (~A); backing up to .bak" c)
        (ignore-errors (bl.kv:rename-path path (%peers-dat-sibling path ".bak")))
        nil))))

(defun %load-core-peers-dat (book path data network)
  "Core LoadAddrman's three outcomes for a file that exists (addrdb.cpp:197-228):
it loads; it is from an incompatible future format, and is backed up and
replaced by an empty one; or it is corrupt, and startup stops with Core's
sentence."
  (let ((start (get-internal-real-time))
        (fresh (make-address-book)))
    (handler-case
        (progn
          (decode-peers-dat data fresh network)
          (%adopt-address-book book fresh)
          (bl.log:log-info "Loaded ~D addresses from peers.dat  ~Dms"
                           (address-book-count book)
                           (round (* 1000 (- (get-internal-real-time) start))
                                  internal-time-units-per-second))
          (bl.log:log-cat "net" "  (~D of them tried)" (address-book-n-tried book))
          (plusp (address-book-count book)))
      (addrman-version-error ()
        (bl.kv:rename-path path (%peers-dat-sibling path ".bak"))
        (bl.log:log-warn "Creating new peers.dat because the file version was not compatible (\"~A\"). Original backed up to peers.dat.bak"
                         (namestring path))
        (save-address-book book path network)
        nil)
      (error (c)
        (init-error "Invalid or corrupt peers.dat (~A). If you believe this is a bug, please report it to ~A. As a workaround, you can move the file (\"~A\") out of the way (rename, move, or delete) to have a new one created on the next start."
                    c "https://github.com/samdefmacro/bitcoin-lisp/issues"
                    (namestring path))))))

(defun load-address-book (book path &optional (network bl.chain:*network*))
  "Core LoadAddrman (addrdb.cpp:197-228): fill BOOK from the peers.dat at PATH
for NETWORK. Returns T when addresses were loaded.

A file in this node's former format is read and rewritten in Core's
(%LOAD-LEGACY-PEERS-DAT); anything else is read as Core's, and a corrupt one
refuses startup with Core's INIT-ERROR, as it does in Core."
  ;; A missing file is not an empty load: Core's DeserializeFileDB throws
  ;; DbNotFoundError, LoadAddrman says so in its own words and writes the
  ;; (empty) address book out at once (addrdb.cpp:208-212), and the functional
  ;; framework waits for exactly that line whenever it deletes peers.dat
  ;; (test_framework.py:540-544, rpc_net.py:343). "Loaded 0 addresses" is what
  ;; Core logs on the NEXT start, reading the file this one wrote
  ;; (feature_addrman.py:65, feature_config_args.py:307).
  (unless (probe-file path)
    (bl.log:log-info "Creating peers.dat because the file was not found (\"~A\")"
                     (namestring path))
    (handler-case (save-address-book book path network)
      (error (c)
        (bl.log:log-warn "Failed to write a new peers.dat: ~A" c)))
    (return-from load-address-book nil))
  (let ((data (alexandria:read-file-into-byte-vector path)))
    (if (and (>= (length data) 4) (equalp (subseq data 0 4) +addrman-magic+))
        (%load-legacy-peers-dat book path data network)
        (%load-core-peers-dat book path data network))))

;;;; anchors.dat (DumpAnchors / ReadAnchors, addrdb.cpp:230-246)

(defun encode-anchors-dat (addresses network)
  "The anchors.dat Core's DumpAnchors writes for ADDRESSES (peer-address
records) on NETWORK: message start, a CompactSize count, each CAddress in the
V2_DISK form, and SHA256d over all of it (addrdb.cpp:230-234 through
SerializeDB)."
  (let ((body (bl.bytes:with-byte-buf (bb)
                (bl.bytes:bb-write-bytes bb (bl.chain:network-magic network))
                (bl.bytes:bb-write-varint bb (length addresses))
                (dolist (pa addresses) (%write-caddress-disk bb pa)))))
    (concatenate '(simple-array (unsigned-byte 8) (*)) body (bl.crypto:hash256 body))))

(defun decode-anchors-dat (bytes network)
  "Core ReadAnchors' read (addrdb.cpp:236-246): the anchors in BYTES as
peer-address records, an address this node cannot hold left out. Signals
ADDRDB-READ-ERROR for a wrong network, a short file or a bad checksum -- which
ReadAnchors turns into no anchors at all."
  (let ((rd (%make-addrdb-reader bytes)))
    (unless (equalp (%rd-bytes rd 4) (bl.chain:network-magic network))
      (%addrdb-fail nil "Invalid network magic number"))
    (let ((anchors
            (loop repeat (%rd-compact-size rd)
                  for (net ip port services time)
                    = (multiple-value-list (%read-caddress-disk rd t))
                  when (%addrinfo-valid-p net ip)
                    collect (make-peer-address :net net :ip ip :port port
                                               :services services :last-seen time))))
      ;; The hash covers what was read, so take it BEFORE reading the
      ;; checksum itself.
      (let ((expected (bl.crypto:hash256 (subseq bytes 0 (%addrdb-reader-pos rd)))))
        (unless (equalp (%rd-bytes rd 32) expected)
          (%addrdb-fail nil "Checksum mismatch, data corrupted")))
      anchors)))
