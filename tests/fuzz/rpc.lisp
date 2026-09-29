(in-package #:bitcoin-lisp.tests)

;;;; Core's RPC-value target at the pin: fuzz/parse_univalue.cpp.

(def-suite :fuzz-rpc-tests :in :bitcoin-lisp-tests
  :description "Core fuzz parse_univalue.cpp target")

(in-suite :fuzz-rpc-tests)

(defun %json-corpus (fdp)
  "A JSON value of the shapes RPC arguments take: strings of hex and of hash
length, numbers written every way JSON allows, arrays and objects of them."
  (labels ((value (depth)
             (call-one-of fdp
               (format nil "\"~A\"" (bl.crypto:bytes-to-hex (consume-bytes fdp (pick-value-in-array fdp '(0 1 20 32 33)))))
               (format nil "\"~A\"" (pick-value-in-array fdp '("ALL" "NONE|ANYONECANPAY" "all" "DEFAULT" "0.1" "1e-8" "-1" "21000001")))
               (format nil "~A~D~A~A" (pick-value-in-array fdp '("" "-")) (consume-integral fdp :u32)
                       (pick-value-in-array fdp '("" ".5" ".00000001" ".123456789"))
                       (pick-value-in-array fdp '("" "e-8" "e3" "E+2")))
               (pick-value-in-array fdp '("null" "true" "false" "[]" "{}"))
               (if (< depth 2)
                   (format nil "[~{~A~^,~}]" (loop repeat (consume-integral-in-range fdp 0 3) collect (value (1+ depth))))
                   "0")
               (if (< depth 2)
                   (format nil "{~{\"k~D\":~A~^,~}}"
                           (loop for i below (consume-integral-in-range fdp 0 2) append (list i (value (1+ depth)))))
                   "1"))))
    (%octets-of-string (value 0))))

(define-fuzz-target parse-univalue
    (buffer :core "parse_univalue.cpp:18-95" :iterations 10000 :max-len 200
            :corpus #'%json-corpus)
  "Any text an RPC client sends as an argument: the request either fails to
parse with Core's error or yields a value that ParseHashV, ParseHexV,
ParseSighashString, AmountFromValue and ParseDescriptorRange each accept or
refuse with an RPC error -- nothing else escapes (Core catches only UniValue
and runtime_error there)."
  (let ((text (map 'string #'code-char buffer)))
    (multiple-value-bind (kind method params)
        (handler-case (bl.rpc:parse-json-rpc-request
                       (format nil "{\"method\":\"fuzz\",\"params\":[~A]}" text))
          (bl.rpc:rpc-error () (fuzz-reject)))
      (declare (ignore method))
      (fuzz-assert (eq (fuzz-sabotage kind) :single) "a request object parsed as ~S" kind)
      (let ((value (first params)))
        (macrolet ((refusable (form) `(handler-case ,form (bl.rpc:rpc-error () nil))))
          (refusable (bl.rpc:parse-hash-v value "A"))
          (refusable (bl.rpc:parse-hash-v value text))
          (refusable (bl.rpc:parse-hex-v value "A"))
          (refusable (bl.rpc:parse-hex-v value text))
          (when (or (null value) (stringp value))
            (refusable (bl.rpc:parse-sighash-type value)))
          (refusable (bl.rpc:amount-from-value value))
          (refusable (bl.rpc:amount-from-value value 3))
          (refusable (bl.rpc:parse-descriptor-range value)))))))
