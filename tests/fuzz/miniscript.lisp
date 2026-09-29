(in-package #:bitcoin-lisp.tests)

;;;; Core's miniscript targets at the pin: fuzz/miniscript.cpp's
;;;; miniscript_string and miniscript_script (the round trips through text and
;;;; through script). miniscript_stable and miniscript_smart drive Core's own
;;;; node generator and satisfier over its test key/preimage tables; they have
;;;; no counterpart here yet.

(def-suite :fuzz-miniscript-tests :in :bitcoin-lisp-tests
  :description "Core fuzz miniscript.cpp targets")

(in-suite :fuzz-miniscript-tests)

(defun %ms-key-text (fdp ctx)
  "A key argument in CTX's own form: a compressed key in P2WSH, x-only in
tapscript (miniscript.h:1060-1075)."
  (let* ((scalar (consume-uint256 fdp))
         (pub (if (bl.crypto:valid-private-key-p scalar)
                  (bl.crypto:derive-public-key scalar :compressed t)
                  (bl.crypto:derive-public-key (%bytes 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
                                                       0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1)
                                               :compressed t))))
    (bl.crypto:bytes-to-hex (if (eq ctx :tapscript) (subseq pub 1) pub))))

(defun %ms-expression (fdp ctx depth)
  "A miniscript expression from Core's fragment table, well-typed or not: the
type checker is part of what the round trips exercise."
  (flet ((sub () (%ms-expression fdp ctx (1+ depth)))
         (hash-hex (n) (bl.crypto:bytes-to-hex
                        (let ((v (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
                          (replace v (consume-bytes fdp n))))))
    (if (or (>= depth 3) (not (consume-bool fdp)))
        (call-one-of fdp
          (format nil "pk(~A)" (%ms-key-text fdp ctx))
          (format nil "pk_h(~A)" (%ms-key-text fdp ctx))
          (format nil "pk_k(~A)" (%ms-key-text fdp ctx))
          (format nil "older(~D)" (consume-integral-in-range fdp 0 #x80000000))
          (format nil "after(~D)" (consume-integral-in-range fdp 0 #x80000000))
          (format nil "sha256(~A)" (hash-hex 32))
          (format nil "hash256(~A)" (hash-hex 32))
          (format nil "ripemd160(~A)" (hash-hex 20))
          (format nil "hash160(~A)" (hash-hex 20))
          "0" "1"
          (format nil "~A(~D,~{~A~^,~})" (if (eq ctx :tapscript) "multi_a" "multi")
                  (consume-integral-in-range fdp 0 3)
                  (loop repeat (consume-integral-in-range fdp 1 3) collect (%ms-key-text fdp ctx))))
        (call-one-of fdp
          (format nil "~A:~A" (pick-value-in-array fdp '("a" "s" "c" "d" "v" "j" "n" "t" "l" "u")) (sub))
          (format nil "and_v(~A,~A)" (sub) (sub))
          (format nil "and_b(~A,~A)" (sub) (sub))
          (format nil "and_n(~A,~A)" (sub) (sub))
          (format nil "or_b(~A,~A)" (sub) (sub))
          (format nil "or_c(~A,~A)" (sub) (sub))
          (format nil "or_d(~A,~A)" (sub) (sub))
          (format nil "or_i(~A,~A)" (sub) (sub))
          (format nil "andor(~A,~A,~A)" (sub) (sub) (sub))
          (format nil "thresh(~D,~{~A~^,~})" (consume-integral-in-range fdp 0 3)
                  (loop repeat (consume-integral-in-range fdp 1 3) collect (sub)))))))

(defun %ms-parse-or-nil (string ctx)
  (handler-case (let ((node (bl.val:ms-parse string :ctx ctx)))
                  (and (bl.val:ms-node-valid-p node) node))
    (bl.val:miniscript-parse-error () nil)))

(define-fuzz-target miniscript-string
    (buffer :core "miniscript.cpp:1235-1252" :iterations 10000 :max-len 400
            :corpus (lambda (fdp)
                      (let ((ctx (if (consume-bool fdp) :tapscript :p2wsh)))
                        (concatenate '(simple-array (unsigned-byte 8) (*))
                                     (%octets-of-string (%ms-expression fdp ctx 0))
                                     (%bytes (if (eq ctx :tapscript) 1 0))))))
  "A miniscript that parses from text prints as text that parses to the same
miniscript: the same canonical string and the same script (Core compares the
two nodes)."
  (when (zerop (length buffer)) (fuzz-reject))
  (let* ((ctx (if (oddp (aref buffer (1- (length buffer)))) :tapscript :p2wsh))
         (node (%ms-parse-or-nil (map 'string #'code-char (subseq buffer 0 (1- (length buffer)))) ctx)))
    (when node
      (let* ((text (bl.val:ms-node-to-string node))
             (again (%ms-parse-or-nil text ctx)))
        (fuzz-assert again "~S prints as ~S, which does not parse under ~S" node text ctx)
        (fuzz-assert (string= (fuzz-sabotage (bl.val:ms-node-to-string again)) text)
                     "~S does not print back as itself" text)
        (fuzz-assert (equalp (bl.val:ms-node-script node) (bl.val:ms-node-script again))
                     "~S compiles differently after a round trip through text" text)))))

(define-fuzz-target miniscript-script
    (buffer :core "miniscript.cpp:1255-1266" :iterations 10000 :max-len 400
            :corpus (lambda (fdp)
                      (let* ((ctx (if (consume-bool fdp) :tapscript :p2wsh))
                             (node (%ms-parse-or-nil (%ms-expression fdp ctx 0) ctx))
                             (script (if node (bl.val:ms-node-script node) (consume-script fdp))))
                        (concatenate '(simple-array (unsigned-byte 8) (*))
                                     (fdp-random-length-bytes (%ser #'bl.bytes:bb-write-var-bytes script))
                                     (%bytes (if (eq ctx :tapscript) 1 0))))))
  "A script that FromScript infers a miniscript from is exactly the script that
miniscript compiles to (ToScript == the input), in P2WSH and in tapscript."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (script (consume-deserializable fdp (lambda (b) (bl.ser:br-read-var-bytes (bl.ser:make-byte-reader-from b)))))
         (ctx (if (consume-bool fdp) :tapscript :p2wsh)))
    (when script
      (let ((node (bl.val:ms-from-script script :ctx ctx)))
        (when node
          (fuzz-assert (equalp (fuzz-sabotage (bl.val:ms-node-script node)) script)
                       "~A infers ~S under ~S, which compiles to other bytes"
                       (bl.crypto:bytes-to-hex script) (bl.val:ms-node-to-string node) ctx))))))
