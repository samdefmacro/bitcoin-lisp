(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/torcontrol.cpp at the pin: TorController's reply
;;;; callbacks -- add_onion_cb, auth_cb, authchallenge_cb, protocolinfo_cb --
;;;; fed replies of any code and any lines. Ours issues the same command
;;;; chain synchronously on the torcontrol thread (the structural divergence
;;;; torcontrol.lisp states), so the target is that thread against a scripted
;;;; control port (%FAKE-TOR-SERVER) that answers every command with the
;;;; buffer's reply: usually 250, else 510 or any code, and lines that are
;;;; usually the protocol's own shapes (AUTH METHODS=..., AUTHCHALLENGE SERVERHASH=...,
;;;; net/listeners/socks=..., ServiceID=..., PrivateKey=...) and now any
;;;; text.
;;;;
;;;; Core asserts only that the callbacks return. Ours: the session never
;;;; meets a condition it does not declare (the thread logs `control session
;;;; error' for those, Core's crash); a service is advertised only for a
;;;; ServiceID a 250 reply to ADD_ONION carried; and it is forgotten when the
;;;; controller stops. A run costs about a second -- the client polls its
;;;; socket once a second for the stop flag -- so the budget is small.

(def-suite :fuzz-torcontrol-tests :in :bitcoin-lisp-tests
  :description "Core fuzz torcontrol.cpp over our control-port client")

(in-suite :fuzz-torcontrol-tests)

(defun %fuzz-tor-text (fdp)
  "Any text that fits on one control-port line."
  (remove-if (lambda (c) (member c '(#\Return #\Newline)))
             (consume-random-length-string fdp 80)))

(defun %fuzz-tor-hex (fdp)
  (bl.crypto:bytes-to-hex (consume-bytes fdp 32)))

(defun %fuzz-tor-reply-lines (fdp command service-ids)
  "The content lines of a reply to COMMAND: the lines Tor sends for it, with
one now and then replaced by any text, dropped, or joined by another. A
ServiceID offered is pushed onto the cell SERVICE-IDS."
  (let ((lines
          (cond ((uiop:string-prefix-p "PROTOCOLINFO" command)
                 (list "PROTOCOLINFO 1"
                       (format nil "AUTH METHODS=~A COOKIEFILE=\"~A\""
                               (pick-value-in-array fdp '("NULL" "NULL" "SAFECOOKIE" "HASHEDPASSWORD"
                                                          "NULL,SAFECOOKIE" "COOKIE"))
                               (%fuzz-tor-text fdp))
                       (format nil "VERSION Tor=\"~A\"" (%fuzz-tor-text fdp))
                       "OK"))
                ((uiop:string-prefix-p "AUTHCHALLENGE" command)
                 (list (format nil "AUTHCHALLENGE SERVERHASH=~A SERVERNONCE=~A"
                               (%fuzz-tor-hex fdp) (%fuzz-tor-hex fdp))))
                ((uiop:string-prefix-p "GETINFO" command)
                 (list (format nil "net/listeners/socks=\"~A\""
                               (pick-value-in-array fdp (list "127.0.0.1:9050" "[::1]:9050"
                                                              (%fuzz-tor-text fdp))))
                       "OK"))
                ((uiop:string-prefix-p "ADD_ONION" command)
                 (let ((sid (if (plusp (consume-integral-in-range fdp 0 3))
                                (subseq (bl.net:onion-address-string (consume-uint256 fdp)) 0 56)
                                (%fuzz-tor-text fdp))))
                   (push sid (car service-ids))
                   (list (format nil "ServiceID=~A" sid)
                         (format nil "PrivateKey=ED25519-V3:~A" (%fuzz-tor-text fdp))
                         "OK")))
                (t (list "OK")))))
    (call-one-of fdp
      lines
      lines
      (let ((i (consume-integral-in-range fdp 0 (1- (length lines)))))
        (append (subseq lines 0 i) (list (%fuzz-tor-text fdp)) (nthcdr (1+ i) lines)))
      (or (remove (pick-value-in-array fdp lines) lines :count 1) (list (%fuzz-tor-text fdp)))
      (append lines (list (%fuzz-tor-text fdp))))))

(defun %fuzz-tor-reply (fdp command service-ids)
  "The wire lines of a reply to COMMAND: its code on every line, `-' between
lines and ` ' on the last. A 250 reply's ServiceIDs are recorded."
  (let* ((code (call-one-of fdp 250 250 250 510 (consume-integral-in-range fdp 100 999)))
         (offered (list '()))
         (lines (%fuzz-tor-reply-lines fdp command offered)))
    (when (eql code 250)
      (setf (car service-ids) (append (car offered) (car service-ids))))
    (loop for (line . more) on lines
          collect (format nil "~D~:[ ~;-~]~A" code more line))))

(defun %log-lines-matching (substring)
  (count-if (lambda (e) (and (stringp e) (search substring e)))
            (bl.log:log-ring-lines bl.log:*log-buffer*)))

(define-fuzz-target torcontrol
    (buffer :core "torcontrol.cpp:33-86" :iterations 5 :max-len 800)
  "The control-port client answered anything at all never meets a condition
it does not declare; it advertises a service only for a ServiceID an ADD_ONION
reply of 250 carried, and forgets it when it stops."
  (let ((fdp (make-fuzzed-data-provider buffer))
        (service-ids (list '()))
        (errors-before (%log-lines-matching "control session error")))
    (with-tor-globals
      (let ((dir (%torcontrol-temp-dir)))
        (multiple-value-bind (port thread received)
            (%fake-tor-server (lambda (command) (%fuzz-tor-reply fdp command service-ids)))
          (let ((ctl (bl.net:start-tor-control
                      :control-spec (format nil "127.0.0.1:~D" port) :data-directory dir
                      :password (when (zerop (consume-integral-in-range fdp 0 3)) "pass\"word")
                      :virtual-port 48333 :target-port 48334)))
            (unwind-protect
                 (progn
                   ;; The session has said what it will say once no command
                   ;; arrives for a tenth of a second.
                   (loop with seen = -1
                         repeat 30
                         until (= seen (length (funcall received)))
                         do (setf seen (length (funcall received)))
                            (sleep 0.1))
                   (let ((advertised (remove :torv3 (bl.net:local-addresses)
                                             :key #'bl.net:local-address-network :test-not #'eq)))
                     (dolist (la advertised)
                       (fuzz-assert (member (fuzz-sabotage
                                             (subseq (bl.net:onion-address-string (bl.net:local-address-bytes la))
                                                     0 56))
                                            (car service-ids) :test #'string=)
                                    "advertised a service no 250 ADD_ONION reply named"))))
              (bl.net:stop-tor-control ctl)
              (ignore-errors (bt:join-thread thread))
              (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))
            (fuzz-assert (notany (lambda (la) (eq :torv3 (bl.net:local-address-network la)))
                                 (bl.net:local-addresses))
                         "the service is still advertised after the controller stopped")
            (fuzz-assert (= errors-before (fuzz-sabotage (%log-lines-matching "control session error")))
                         "the session met a condition it does not declare")))))))
