(in-package #:bitcoin-lisp.tests)

;;;; Core's address-manager targets at the pin: fuzz/addrman.cpp
;;;; (data_stream_addr_man, addrman, addrman_serdeser). Our address book stores
;;;; Core's peers.dat, so the file half ports byte for byte; CheckAddrman is
;;;; CHECK-ADDRESS-BOOK, which is what Core's -checkaddrman=1 runs after every
;;;; operation in these targets.

(def-suite :fuzz-addrman-tests :in :bitcoin-lisp-tests
  :description "Core fuzz addrman.cpp targets")

(in-suite :fuzz-addrman-tests)

(defmacro with-fuzz-addrman-clock ((fdp) &body body)
  "Core's SeedRandomStateForTest(SeedRand::ZEROS) and SetMockTime(ConsumeTime):
the address book's randomness and clock are functions of the input."
  `(let ((*random-state* (sb-ext:seed-random-state 0))
         (bl.ser:*mock-time* (consume-integral-in-range ,fdp 946684801 4133980799)))
     ,@body))

(defun %rand-addr (fdp)
  "Core RandAddr (addrman.cpp:57-76): a routable address from the input, or
5.5.5.5 when eight draws gave none. (values network bytes)."
  (loop repeat 8
        do (multiple-value-bind (network bytes) (consume-net-addr fdp)
             (when (bl.net:address-routable-p bytes network)
               (return-from %rand-addr (values network bytes)))))
  (values :ipv4 (%bytes 0 0 0 0 0 0 0 0 0 0 #xff #xff 5 5 5 5)))

(defun %book-add (book fdp network bytes port source-network source-bytes penalty)
  (bl.net:address-book-add
   book
   (bl.net:make-peer-address :net network :ip bytes :port port
                             :services (consume-integral fdp :u64)
                             :last-seen (ldb (byte 32 0) (bl.ser:get-unix-time)))
   (bl.net:net-group-key source-bytes source-network)
   penalty))

(defun %fill-addrman (book fdp)
  "Core FillAddrman (addrman.cpp:78-113) at a tenth of its size: addresses
from several sources, a fraction of them promoted with Good, one in ten
re-added from the previous source."
  (let ((n (consume-integral-in-range fdp 0 3))
        (prev nil))
    (loop repeat (consume-integral-in-range fdp 1 5)
          do (multiple-value-bind (snet sbytes) (%rand-addr fdp)
               (loop repeat (1+ (consume-integral-in-range fdp 0 49))
                     do (multiple-value-bind (net bytes) (%rand-addr fdp)
                          (let ((penalty (consume-integral-in-range fdp 0 100000000)))
                            (%book-add book fdp net bytes 8333 snet sbytes penalty)
                            (when (and (plusp n) (zerop (mod (bl.net:address-book-count book) n)))
                              (bl.net:address-book-good book bytes 8333 (bl.ser:get-unix-time) net))
                            (when (and prev (zerop (consume-integral-in-range fdp 0 9)))
                              (%book-add book fdp net bytes 8333 (car prev) (cdr prev) penalty)))))
               (setf prev (cons snet sbytes))))))

(define-fuzz-target data-stream-addr-man
    (buffer :core "addrman.cpp:42-53" :iterations 600 :max-len 3000
            :corpus (lambda (fdp)
                      (with-fuzz-addrman-clock (fdp)
                        (let ((book (bl.net:make-address-book)))
                          (%fill-addrman book fdp)
                          (bl.net:encode-peers-dat book :regtest)))))
  "Reading a peers.dat from arbitrary bytes into an empty address book either
fails with one of the reader's declared errors (Core catches the
std::exception ReadFromStream throws) or yields a book whose every index
agrees with every other -- CheckAddrman returns 0."
  (let ((*random-state* (sb-ext:seed-random-state 0))
        (book (bl.net:make-address-book)))
    (fuzz-deserialize (bl.net:decode-peers-dat buffer book :regtest)
                      :declared '(or bl.net:addrdb-read-error bl.err:serialization-error))
    (fuzz-assert (zerop (fuzz-sabotage (bl.net:check-address-book book)))
                 "a peers.dat that loads fails CheckAddrman")))

(define-fuzz-target addrman
    (buffer :core "addrman.cpp:115-209" :iterations 600 :max-len 1500)
  "Any sequence of Add, Good, Attempt, Connected, SelectTriedCollision and
ResolveCollisions -- over a book filled first, or loaded from bytes -- leaves
CheckAddrman at 0 after every operation (Core runs it with -checkaddrman=1),
and GetAddr, Select and serialization answer at the end."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-addrman-clock (fdp)
      (let ((book (bl.net:make-address-book)))
        (when (consume-bool fdp)
          (handler-case (bl.net:decode-peers-dat (consume-random-length-byte-vector fdp) book :regtest)
            (bl.net:addrdb-read-error () (setf book (bl.net:make-address-book)))))
        (flet ((service () (multiple-value-bind (net bytes) (consume-net-addr fdp)
                             (values net bytes (consume-integral fdp :u16))))
               (clock () (consume-integral-in-range fdp 946684801 4133980799)))
          (limited-while ((consume-bool fdp) 10000)
            (call-one-of fdp
              (bl.net:resolve-tried-collisions book (clock))
              (bl.net:select-tried-collision book)
              (multiple-value-bind (snet sbytes) (consume-net-addr fdp)
                (limited-while ((consume-bool fdp) 10000)
                  (multiple-value-bind (net bytes port) (service)
                    (%book-add book fdp net bytes port snet sbytes
                               (consume-integral-in-range fdp 0 100000000)))))
              (multiple-value-bind (net bytes port) (service)
                (bl.net:address-book-good book bytes port (clock) net))
              (multiple-value-bind (net bytes port) (service)
                (bl.net:address-book-attempt book bytes port
                                             :count-failure (consume-bool fdp) :now (clock) :net net))
              (multiple-value-bind (net bytes port) (service)
                (bl.net:address-book-connected book bytes port (clock) net)))
            (fuzz-assert (zerop (fuzz-sabotage (bl.net:check-address-book book)))
                         "CheckAddrman failed after an operation")))
        (bl.net:address-book-get-addr book :max (consume-integral-in-range fdp 0 4096)
                                           :pct (consume-integral-in-range fdp 0 100))
        (bl.net:address-book-select book :new-only (consume-bool fdp))
        (bl.net:encode-peers-dat book :regtest)))))

(define-fuzz-target addrman-serdeser
    (buffer :core "addrman.cpp:211-229" :iterations 300 :max-len 1500)
  "Serialize followed by unserialize produces the same address book: the
book read back from the peers.dat a filled book writes writes the same
peers.dat (Core compares the two AddrManDeterministics entry by entry and
bucket by bucket)."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-fuzz-addrman-clock (fdp)
      (let ((book (bl.net:make-address-book))
            (again (bl.net:make-address-book)))
        (%fill-addrman book fdp)
        (let ((bytes (bl.net:encode-peers-dat book :regtest)))
          (bl.net:decode-peers-dat bytes again :regtest)
          (fuzz-assert (equalp bytes (fuzz-sabotage (bl.net:encode-peers-dat again :regtest)))
                       "a book of ~D addresses does not survive its peers.dat"
                       (bl.net:address-book-count book)))))))
