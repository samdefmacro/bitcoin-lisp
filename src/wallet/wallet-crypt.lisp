(in-package #:bitcoin-lisp.wallet)

;;; Wallet P6: encryption, passphrase lifecycle, and backup/restore
;;; (docs/wallet-plan.md §5 P6)
;;;
;;; Ports, from Bitcoin Core @ d3056bc:
;;;  - CWallet::EncryptWallet / Unlock / Lock / ChangeWalletPassphrase
;;;    (wallet.cpp:580-671, 808-881, 3351-3390) and
;;;    DescriptorScriptPubKeyMan::Encrypt / CheckDecryptionKey
;;;    (scriptpubkeyman.cpp:869-922).
;;;  - The four encryption RPCs (wallet/rpc/encrypt.cpp) and
;;;    backupwallet/restorewallet (wallet/rpc/backup.cpp:574-680).
;;;
;;; Only KEY MATERIAL is encrypted. Descriptors, transactions, the address
;;; book and every other record stay plaintext, exactly as in Core — an
;;; encrypted wallet still tracks the chain and reports balances while
;;; locked, it just cannot sign.
;;;
;;; The crypto primitives themselves live in src/crypto/crypter.lisp.

(defconstant +master-key-default-derive-iterations+ 25000
  "CMasterKey::DEFAULT_DERIVE_ITERATIONS (crypter.h:48), also the floor the
calibration is allowed to settle on.")

(defconstant +master-key-max-derive-iterations+ 20000000
  "Our own ceiling on the calibrated iteration count; Core has none.

The calibration measures this machine and bakes the result into the wallet
file forever. This host shares its CPU with other containers, so a
calibration run under heavy load can settle on a number that makes every
later unlock take many seconds on an idle machine. 20M is ~50x the count a
healthy run produces here and still well above anything a wallet needs.")

(defconstant +kdf-target-milliseconds+ 100
  "EncryptMasterKey's target time for one key derivation (wallet.cpp:588).")

(defconstant +walletpassphrase-max-sleep-time+ 100000000
  "MAX_SLEEP_TIME (encrypt.cpp:64): the timeout is silently clamped here.")

;;; --- Secret-level helpers (Core crypter.cpp EncryptSecret/DecryptSecret) ---

(defun passphrase-octets (string)
  "The passphrase as bytes. Core treats a SecureString as raw bytes with no
terminator, so embedded NULs are part of the passphrase — see the dedicated
NUL-in-passphrase error message the RPCs emit."
  (coerce (flexi-streams:string-to-octets string :external-format :utf-8)
          '(simple-array (unsigned-byte 8) (*))))

(defun %secret-iv (pubkey)
  "The per-key IV: the first 16 bytes of sha256d over the SERIALIZED pubkey
(Core EncryptSecret's nIV = CPubKey::GetHash(), pubkey.h:165).

Note GetHash is the double-SHA256, NOT the Hash160 that GetID (the map key)
uses, and the bytes are taken in natural digest order — never reversed, and
never via a display-hex round trip."
  (subseq (bl.crypto:hash256 pubkey) 0 16))

(defun encrypt-secret (master-key32 secret32 pubkey)
  "Core EncryptSecret: AES-256-CBC the bare 32-byte secret scalar under the
master key, keyed by the pubkey-derived IV. Note it is the raw scalar, not
the DER CPrivKey our plaintext records store."
  (bl.crypto:aes-256-cbc-encrypt master-key32 (%secret-iv pubkey)
                                           secret32))

(defun decrypt-secret (master-key32 ciphertext pubkey)
  "Core DecryptSecret. NIL on any failure."
  (bl.crypto:aes-256-cbc-decrypt master-key32 (%secret-iv pubkey)
                                           ciphertext))

(defun decrypt-key (master-key32 pubkey ciphertext)
  "Core DecryptKey: decrypt and prove the result is the secret for PUBKEY.
Returns the 32-byte secret, or NIL.

The pubkey check is what makes a wrong master key fail loudly instead of
producing a valid-looking but wrong signing key. We re-derive the pubkey
rather than doing Core's sign-and-verify round trip — deterministic,
cheaper, and strictly stronger. VALID-PRIVATE-KEY-P has to come first:
DERIVE-PUBLIC-KEY signals on an out-of-range scalar."
  (let ((secret (decrypt-secret master-key32 ciphertext pubkey)))
    (when (and secret
               (= (length secret) 32)
               (bl.crypto:valid-private-key-p secret)
               (equalp (bl.crypto:derive-public-key
                        secret :compressed (= (length pubkey) 33))
                       pubkey))
      secret)))

;;; --- Master key: derive, wrap, unwrap (Core Encrypt/DecryptMasterKey) ---

(defun %derive-master-key-parts (passphrase mk)
  "(values key32 iv16) for MK's KDF parameters, or (values NIL NIL)."
  (bl.crypto:crypter-derive-key
   (passphrase-octets passphrase)
   (wallet-master-key-salt mk)
   (wallet-master-key-derive-iterations mk)
   (wallet-master-key-derivation-method mk)))

(defun decrypt-master-key (passphrase mk)
  "The plaintext 32-byte master key wrapped in MK, or NIL when PASSPHRASE is
wrong (Core DecryptMasterKey, wallet.cpp:607-618).

A wrong passphrase yields a random block whose chance of unpadding to
exactly 32 bytes is negligible, so this doubles as the passphrase check."
  (multiple-value-bind (key iv) (%derive-master-key-parts passphrase mk)
    (when key
      (let ((plain (bl.crypto:aes-256-cbc-decrypt
                    key iv (wallet-master-key-crypted-key mk))))
        (when (and plain (= (length plain)
                            bl.crypto:+wallet-crypto-key-size+))
          plain)))))

(defun %time-derivation (passphrase salt iterations)
  "Milliseconds one KDF run of ITERATIONS takes, at least 1 (Core divides by
this, and a zero duration would be a division by zero)."
  (let ((start (get-internal-real-time)))
    (bl.crypto:crypter-derive-key (passphrase-octets passphrase)
                                            salt iterations 0)
    (max 1 (round (* 1000 (- (get-internal-real-time) start))
                  internal-time-units-per-second))))

(defun encrypt-master-key (passphrase plain-master32 salt start-iterations)
  "Wrap PLAIN-MASTER32 under a passphrase-derived key, calibrating the
iteration count so one derivation costs about +KDF-TARGET-MILLISECONDS+ on
this machine (Core EncryptMasterKey, wallet.cpp:580-605). Returns a
WALLET-MASTER-KEY, or NIL if derivation fails.

Core's two-measurement average is kept verbatim; the ceiling is ours."
  (let* ((first-ms (%time-derivation passphrase salt start-iterations))
         (iterations (truncate (* start-iterations +kdf-target-milliseconds+)
                               first-ms))
         (second-ms (%time-derivation passphrase salt iterations)))
    (setf iterations
          (truncate (+ iterations
                       (truncate (* iterations +kdf-target-milliseconds+)
                                 second-ms))
                    2))
    (setf iterations (max iterations +master-key-default-derive-iterations+))
    (when (> iterations +master-key-max-derive-iterations+)
      (bl:log-warn
       "KDF calibration produced ~D iterations (the machine was probably loaded); clamping to ~D"
       iterations +master-key-max-derive-iterations+)
      (setf iterations +master-key-max-derive-iterations+))
    (multiple-value-bind (key iv)
        (bl.crypto:crypter-derive-key (passphrase-octets passphrase)
                                                salt iterations 0)
      (when key
        (make-wallet-master-key
         :crypted-key (bl.crypto:aes-256-cbc-encrypt
                       key iv plain-master32)
         :salt salt
         :derivation-method 0
         :derive-iterations iterations)))))

;;; --- Unlock / lock (Core CWallet::Unlock, Lock, CheckDecryptionKey) ---

(defun check-decryption-key (wallet master-key32)
  "T when MASTER-KEY32 decrypts the wallet's keys (Core CheckDecryptionKey,
scriptpubkeyman.cpp:869-899, folded to the wallet level). Signals when some
keys decrypt and others do not — that is file corruption, not a wrong
passphrase, and must not be reported as one.

Unlike Core we re-verify every key on every unlock rather than caching a
thoroughly-checked flag: our wallets hold one key per SPKM, so the whole
check is a handful of AES blocks."
  (let ((any-pass nil)
        (any-fail nil))
    (loop for spkm being the hash-values of (wallet-spkms wallet)
          do ;; A SPKM still holding plaintext keys must never count as
             ;; unlocked (Core: !m_map_keys.empty() -> false).
             (when (plusp (hash-table-count (desc-spkm-keys spkm)))
               (return-from check-decryption-key nil))
             (block spkm-keys
               (maphash (lambda (keyid entry)
                          (declare (ignore keyid))
                          (if (decrypt-key master-key32 (car entry) (cdr entry))
                              (setf any-pass t)
                              (progn (setf any-fail t)
                                     (return-from spkm-keys))))
                        (desc-spkm-crypted-keys spkm))))
    (when (and any-pass any-fail)
      (bl:log-warn
       "The wallet is probably corrupted: Some keys decrypt but not all.")
      (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-error+
                        :message "Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt."))
    (not any-fail)))

(defun unlock-wallet (wallet passphrase)
  "Try PASSPHRASE against every master key; on success stash the decrypted
keying material and return T (Core CWallet::Unlock, wallet.cpp:620-639).

Callers hold the wallet's unlock lock and the wallet lock. This sets no
timer — WALLET-ARM-RELOCK does that — so internal callers (createwallet,
encryptwallet) get an unlock that stays until they explicitly relock."
  (unless (wallet-has-encryption-keys-p wallet)
    (return-from unlock-wallet nil))
  (dolist (id (sort (alexandria:hash-table-keys (wallet-master-keys wallet)) #'<)
              nil)
    (let* ((mk (gethash id (wallet-master-keys wallet)))
           (plain (decrypt-master-key passphrase mk)))
      (when (and plain (check-decryption-key wallet plain))
        ;; Zero any key already held before dropping the reference: calling
        ;; walletpassphrase on an unlocked wallet is legal and would
        ;; otherwise leave the previous master key loose in the heap.
        (let ((previous (wallet-encryption-key wallet)))
          (when previous (fill previous 0)))
        (setf (wallet-encryption-key wallet) plain)
        (return t)))))

(defun lock-wallet (wallet)
  "Drop the decrypted master key (Core CWallet::Lock). NIL when the wallet
is not encrypted — there is nothing to lock."
  (when (wallet-has-encryption-keys-p wallet)
    (with-wallet-lock (wallet)
      (%wallet-clear-encryption-key wallet))
    t))

(defun wallet-arm-relock (wallet timeout)
  "Schedule the relock TIMEOUT seconds from now. RELOCK-TIME is wall clock
because it is what getwalletinfo reports; RELOCK-DEADLINE is monotonic
because it is what actually fires — a backward clock step must never extend
an unlock window."
  (setf (wallet-relock-time wallet)
        (+ (bl.ser:get-unix-time) timeout)
        (wallet-relock-deadline wallet)
        (+ (get-internal-real-time)
           (* timeout internal-time-units-per-second))))

(defun change-wallet-passphrase (wallet old-passphrase new-passphrase)
  "Rewrap the master key under a new passphrase (Core
ChangeWalletPassphrase, wallet.cpp:641-671). T on success.

No descriptor key is re-encrypted: the plaintext master key is unchanged,
so only this one record moves. On every failure path the wallet is left
LOCKED, even if it started unlocked — Core parity, and it forces the caller
to re-prove the passphrase."
  (with-wallet-lock (wallet)
    ;; Sampled under the lock: wallet-is-locked-p can relock as a side
    ;; effect (the lazy deadline check writes three slots), so reading it
    ;; outside would be an unsynchronized mutation.
    (let* ((was-unlocked (and (wallet-has-encryption-keys-p wallet)
                              (not (wallet-is-locked-p wallet))))
           ;; Core's Lock() clears only the key material; nRelockTime is
           ;; zeroed by the walletlock RPC, not here (wallet.cpp:3360,
           ;; encrypt.cpp:206). Preserving the deadline matters: without it
           ;; a passphrase change on a timed unlock would silently leave the
           ;; wallet unlocked forever while getwalletinfo reported 0.
           (saved-relock-time (wallet-relock-time wallet))
           (saved-relock-deadline (wallet-relock-deadline wallet)))
      (%wallet-clear-encryption-key wallet)
      (dolist (id (sort (alexandria:hash-table-keys (wallet-master-keys wallet)) #'<)
                  nil)
        (let* ((mk (gethash id (wallet-master-keys wallet)))
               (plain (decrypt-master-key old-passphrase mk)))
          ;; Core bails on the FIRST master key that will not decrypt here,
          ;; unlike Unlock which tries them all. Keep the divergence.
          (unless plain (return nil))
          (when (check-decryption-key wallet plain)
            (let ((new-mk (encrypt-master-key new-passphrase plain
                                              (wallet-master-key-salt mk)
                                              (wallet-master-key-derive-iterations mk))))
              ;; Prove the new wrapper opens before it replaces the old one.
              (unless (and new-mk
                           (equalp plain (decrypt-master-key new-passphrase new-mk)))
                (return nil))
              ;; Persist before mutating memory: Core ignores the write
              ;; result here and can end up with memory and disk disagreeing
              ;; about which passphrase works.
              (bl.store:leveldb-put
               (wallet-db wallet) (wdb-key-mkey id)
               (wdb-mkey-value (wallet-master-key-crypted-key new-mk)
                               (wallet-master-key-salt new-mk)
                               (wallet-master-key-derivation-method new-mk)
                               (wallet-master-key-derive-iterations new-mk)
                               (wallet-master-key-other-params new-mk))
               :sync t)
              (setf (gethash id (wallet-master-keys wallet)) new-mk)
              (bl:log-info
               "Wallet passphrase changed to an nDeriveIterations of ~D"
               (wallet-master-key-derive-iterations new-mk))
              (when was-unlocked
                ;; Restore the unlock AND the deadline it was carrying, so a
                ;; scheduled relock still fires at its original time.
                (setf (wallet-encryption-key wallet) plain
                      (wallet-relock-time wallet) saved-relock-time
                      (wallet-relock-deadline wallet) saved-relock-deadline))
              (return t))))))))

;;; --- EncryptWallet (Core wallet.cpp:808-881) ---

(defun %wallet-staged-encryptions (wallet plain-master)
  "Encrypt every plaintext key in memory, returning a list of
 (spkm keyid pubkey ciphertext). Signals if any key fails to round-trip.

Nothing here touches the database: the whole point is that a failure at any
point leaves both the file and the in-memory maps exactly as they were."
  (let ((staged '()))
    (loop for spkm being the hash-values of (wallet-spkms wallet)
          do (when (plusp (hash-table-count (desc-spkm-crypted-keys spkm)))
               ;; Core: Encrypt() refuses when m_map_crypted_keys is
               ;; non-empty. A mixed wallet means we would be about to
               ;; wrap already-wrapped keys.
               (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-encryption-failed+
                                 :message "Error: Failed to encrypt the wallet."))
             (maphash
              (lambda (keyid entry)
                (destructuring-bind (priv32 . compressed-p) entry
                  (let* ((pubkey (bl.crypto:derive-public-key
                                  priv32 :compressed compressed-p))
                         (ciphertext (encrypt-secret plain-master priv32 pubkey)))
                    (unless (equalp priv32
                                    (decrypt-key plain-master pubkey ciphertext))
                      (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-encryption-failed+
                                        :message "Error: Failed to encrypt the wallet."))
                    (push (list spkm keyid pubkey ciphertext) staged))))
              (desc-spkm-keys spkm)))
    (nreverse staged)))

(defun encrypt-wallet (wallet passphrase)
  "Encrypt WALLET's key material under PASSPHRASE. T on success; NIL when
the wallet is already encrypted. Leaves the wallet LOCKED.

Core's failure handling here is `assert(false)` — it aborts the process so
the user reloads the pre-encryption file (wallet.cpp:848-862). We cannot do
that, so the ordering below makes a half-encrypted wallet unreachable
instead:

  1. every key is encrypted and verified IN MEMORY before anything is
     written, so any failure leaves the file byte-identical;
  2. the master key record, every ciphertext record, and every plaintext
     deletion go into ONE LevelDB batch, which is atomic — there is no
     interleaving where an mkey exists without its ckeys (a wallet that
     would report itself encrypted with unreachable keys);
  3. in-memory maps are mutated only after the write returns, so a crash
     during the write leaves memory matching the unencrypted file.

A crash after the batch but before the seed rotation leaves a complete,
consistent encrypted wallet that merely kept its old seed."
  (assert (wallet-flag-set-p wallet +wallet-flag-descriptors+))
  (when (wallet-has-encryption-keys-p wallet)
    (return-from encrypt-wallet nil))
  (let* ((plain-master (ironclad:random-data
                        bl.crypto:+wallet-crypto-key-size+))
         (salt (ironclad:random-data
                bl.crypto:+wallet-crypto-salt-size+))
         (mk (encrypt-master-key passphrase plain-master salt
                                 +master-key-default-derive-iterations+)))
    (unless (and mk (equalp plain-master (decrypt-master-key passphrase mk)))
      (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-encryption-failed+
                        :message "Error: Failed to encrypt the wallet."))
    (bl:log-info "Encrypting Wallet with an nDeriveIterations of ~D"
                           (wallet-master-key-derive-iterations mk))
    (with-wallet-lock (wallet)
      (let ((staged (%wallet-staged-encryptions wallet plain-master)))
        (bl.store:with-leveldb-writebatch (batch)
          (bl.store:leveldb-writebatch-put
           batch (wdb-key-mkey 1)
           (wdb-mkey-value (wallet-master-key-crypted-key mk)
                           (wallet-master-key-salt mk)
                           (wallet-master-key-derivation-method mk)
                           (wallet-master-key-derive-iterations mk)
                           (wallet-master-key-other-params mk)))
          (dolist (entry staged)
            (destructuring-bind (spkm keyid pubkey ciphertext) entry
              (declare (ignore keyid))
              (bl.store:leveldb-writebatch-put
               batch
               (wdb-key-descriptor-key +wdb-key-walletdescriptorckey+
                                       (desc-spkm-id spkm) pubkey)
               (wdb-vector-value ciphertext))
              (bl.store:leveldb-writebatch-delete
               batch
               (wdb-key-descriptor-key +wdb-key-walletdescriptorkey+
                                       (desc-spkm-id spkm) pubkey))))
          (bl.store:leveldb-write (wallet-db wallet) batch :sync t))
        ;; The write landed; only now does memory follow.
        (setf (gethash 1 (wallet-master-keys wallet)) mk
              (wallet-master-key-max-id wallet) 1)
        (dolist (entry staged)
          (destructuring-bind (spkm keyid pubkey ciphertext) entry
            (setf (gethash keyid (desc-spkm-crypted-keys spkm))
                  (cons pubkey ciphertext))))
        (loop for spkm being the hash-values of (wallet-spkms wallet)
              do (clrhash (desc-spkm-keys spkm))))
      ;; Core's Lock(); Unlock(passphrase); — the last gate before the
      ;; plaintext becomes unreachable. From here the wallet is UNLOCKED, so
      ;; the relock has to happen on every exit: an error escaping the seed
      ;; rotation would otherwise leave a wallet the user believes is
      ;; encrypted sitting unlocked with no relock deadline armed.
      (unwind-protect
           (progn
             (unless (unlock-wallet wallet passphrase)
               (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-encryption-failed+
                                 :message "Error: Failed to encrypt the wallet."))
             ;; A new seed, so the addresses handed out before encryption are
             ;; not derivable from a backup taken after it (wallet.cpp:868-871).
             ;; The old SPKMs stay loaded and spendable; only generation moves.
             (unless (or (wallet-flag-set-p wallet +wallet-flag-blank-wallet+)
                         (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+))
               (wallet-setup-descriptor-spkms wallet (generate-wallet-master-key
                                                      (wallet-network wallet)))))
        (%wallet-clear-encryption-key wallet)))
    ;; Best-effort analogue of Core's database Rewrite: a LevelDB delete is
    ;; only a tombstone, so the plaintext DER bytes survive in the SST files
    ;; until a compaction drops them. This is NOT an erasure guarantee,
    ;; which is exactly why the RPC tells the user to take a fresh backup.
    (handler-case (bl.store:leveldb-compact (wallet-db wallet))
      (error (e)
        (bl:log-warn "wallet compaction after encryption failed: ~A" e)))
    t))

;;; --- The relock sweeper (wallet P6) ---
;;;
;;; Correctness comes from WALLET-UNLOCKED-KEY, which enforces the deadline
;;; on every read of the key; this thread only provides liveness, so that a
;;; wallet left untouched still relocks on time. Losing the thread can never
;;; leave a key usable past its deadline.
;;;
;;; One thread per manager, not one per unlock: nothing rate-limits
;;; walletpassphrase, and with a clamp of ~3.17 years a loop of calls would
;;; otherwise leak an effectively immortal sleeping thread each time.

(defun %relock-sweep (manager)
  "One pass: relock every wallet whose deadline has passed."
  (dolist (wallet (wallet-manager-wallet-snapshot manager))
    (handler-case
        (when (and (wallet-db wallet)
                   (plusp (wallet-relock-deadline wallet))
                   (not (wallet-scanning-with-passphrase wallet))
                   (>= (get-internal-real-time) (wallet-relock-deadline wallet)))
          ;; Taking the wallet lock is what makes a relock unable to land
          ;; mid-signature: every signing path holds it across
          ;; create -> sign -> verify -> commit.
          (with-wallet-lock (wallet)
            ;; Re-check under the lock: a walletpassphrase that re-armed the
            ;; timer between the test above and this acquisition must not be
            ;; undone by a sweep that decided one tick ago.
            (when (and (plusp (wallet-relock-deadline wallet))
                       (not (wallet-scanning-with-passphrase wallet))
                       (>= (get-internal-real-time)
                           (wallet-relock-deadline wallet)))
              (lock-wallet wallet))))
      (error (e)
        (bl:log-warn "relock sweep failed for wallet ~A: ~A"
                               (wallet-name wallet) e)))))

(defun ensure-relock-sweeper (manager)
  "Start the sweeper if it is not already running. Called on every
successful unlock; idempotent."
  (bt:with-recursive-lock-held ((wallet-manager-lock manager))
    (unless (wallet-manager-relock-running manager)
      (setf (wallet-manager-relock-running manager) t)
      (setf (wallet-manager-relock-thread manager)
            (bt:make-thread
             (lambda ()
               (loop while (wallet-manager-relock-running manager)
                     do (sleep 1)
                        ;; An unhandled error here would kill the thread and
                        ;; silently end all future sweeps.
                        (handler-case (%relock-sweep manager)
                          (error (e)
                            (bl:log-warn "relock sweep pass failed: ~A" e)))))
             :name "wallet-relock")))))

(defun stop-relock-sweeper (manager)
  "Stop and join the sweeper. Safe when it was never started."
  (setf (wallet-manager-relock-running manager) nil)
  (let ((thread (wallet-manager-relock-thread manager)))
    (when thread
      ;; The loop polls the flag every second, so this returns promptly and
      ;; never reaches the destroy fallback.
      (bl.net:join-thread-or-destroy thread)
      (setf (wallet-manager-relock-thread manager) nil))))

;;; --- Encryption RPCs (Core wallet/rpc/encrypt.cpp) ---

(defun %require-passphrase-string (value)
  (unless (stringp value)
    (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                      :message "passphrase must be a string"))
  value)

(defun %require-not-scanning (wallet action)
  "Refuse while a rescan is holding the wallet unlocked across lock drops
(Core IsScanningWithPassphrase). ACTION completes Core's message."
  (when (wallet-scanning-with-passphrase wallet)
    (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-error+
                      :message (format nil "Error: the wallet is currently being used to rescan the blockchain for related transactions. Please call `abortrescan` before ~A." action))))

(defun %passphrase-incorrect-error (passphrase &key oldp)
  "Core's wrong-passphrase error. A passphrase containing a NUL gets the
long explanation, because versions before 25.0 truncated at the first NUL
and such a wallet needs the truncated form to open."
  (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-passphrase-incorrect+
                    :message
                    (cond ((not (find #\Nul passphrase))
                           "Error: The wallet passphrase entered was incorrect.")
                          (oldp
                           "Error: The old wallet passphrase entered is incorrect. It contains a null character (ie - a zero byte). If the old passphrase was set with a version of this software prior to 25.0, please try again with only the characters up to — but not including — the first null character.")
                          (t
                           "Error: The wallet passphrase entered is incorrect. It contains a null character (ie - a zero byte). If the passphrase was set with a version of this software prior to 25.0, please try again with only the characters up to — but not including — the first null character. If this is successful, please set a new passphrase to avoid this issue in the future."))))

(bl.rpc:define-rpc "encryptwallet" (node params)
  "Encrypt an unencrypted wallet (Bitcoin Core encryptwallet).
PARAMS: (passphrase). Returns the instruction string.

Encryption generates a NEW HD seed, so any backup taken before this call
no longer covers the addresses the wallet will hand out next."
  (let ((wallet (wallet-for-request node))
        (passphrase (%require-passphrase-string (first params))))
    (when (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+)
      (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-encryption-failed+
                        :message "Error: wallet does not contain private keys, nothing to encrypt."))
    (when (wallet-has-encryption-keys-p wallet)
      (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-wrong-enc-state+
                        :message "Error: running with an encrypted wallet, but encryptwallet was called."))
    (%require-not-scanning wallet "encrypting the wallet")
    (bt:with-lock-held ((wallet-unlock-lock wallet))
      (with-wallet-lock (wallet)
        (when (zerop (length passphrase))
          (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "passphrase cannot be empty"))
        (unless (encrypt-wallet wallet passphrase)
          (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-encryption-failed+
                            :message "Error: Failed to encrypt the wallet."))))
    "wallet encrypted; The keypool has been flushed and a new HD seed was generated. You need to make a new backup with the backupwallet RPC."))

(bl.rpc:define-rpc "walletpassphrase" (node params)
  "Unlock the wallet for TIMEOUT seconds (Bitcoin Core walletpassphrase).
PARAMS: (passphrase timeout). Returns null.

Calling it on an already-unlocked wallet succeeds and re-arms the timer."
  (let* ((manager (node-wallet-manager-checked node))
         (wallet (wallet-for-request node))
         (passphrase (first params))
         (timeout (second params)))
    ;; The unlock lock is held across the whole handler, KDF included, so
    ;; two concurrent unlocks cannot interleave their timer arming.
    (bt:with-lock-held ((wallet-unlock-lock wallet))
      (with-wallet-lock (wallet)
        (unless (wallet-has-encryption-keys-p wallet)
          (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-wrong-enc-state+
                            :message "Error: running with an unencrypted wallet, but walletpassphrase was called."))
        (%require-passphrase-string passphrase)
        (unless (integerp timeout)
          (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "Timeout must be an integer"))
        (when (minusp timeout)
          (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "Timeout cannot be negative."))
        (let ((timeout (min timeout +walletpassphrase-max-sleep-time+)))
          (when (zerop (length passphrase))
            (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                              :message "passphrase cannot be empty"))
          (unless (unlock-wallet wallet passphrase)
            (%passphrase-incorrect-error passphrase))
          (wallet-arm-relock wallet timeout)
          ;; Core tops up here (encrypt.cpp:87) so an unlock refills the
          ;; keypool the wallet could not extend while locked. It must not
          ;; be able to fail the unlock itself.
          (handler-case
              (progn
                (loop for spkm being the hash-values of (wallet-external-spkms wallet)
                      do (spkm-top-up wallet spkm))
                (loop for spkm being the hash-values of (wallet-internal-spkms wallet)
                      do (spkm-top-up wallet spkm)))
            (error (e)
              (bl:log-warn "keypool top-up after unlock failed: ~A" e))))))
    (ensure-relock-sweeper manager)
    nil))

(bl.rpc:define-rpc "walletpassphrasechange" (node params)
  "Change the wallet passphrase (Bitcoin Core walletpassphrasechange).
PARAMS: (oldpassphrase newpassphrase). Returns null."
  (let ((wallet (wallet-for-request node))
        (old (%require-passphrase-string (first params)))
        (new (%require-passphrase-string (second params))))
    (unless (wallet-has-encryption-keys-p wallet)
      (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-wrong-enc-state+
                        :message "Error: running with an unencrypted wallet, but walletpassphrasechange was called."))
    (%require-not-scanning wallet "changing the passphrase")
    (bt:with-lock-held ((wallet-unlock-lock wallet))
      (with-wallet-lock (wallet)
        (when (or (zerop (length old)) (zerop (length new)))
          (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "passphrase cannot be empty"))
        (unless (change-wallet-passphrase wallet old new)
          (%passphrase-incorrect-error old :oldp t))))
    nil))

(bl.rpc:define-rpc "walletlock" (node params)
  "Relock the wallet (Bitcoin Core walletlock). Returns null."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (unless (wallet-has-encryption-keys-p wallet)
      (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-wrong-enc-state+
                        :message "Error: running with an unencrypted wallet, but walletlock was called."))
    (%require-not-scanning wallet "locking the wallet")
    (with-wallet-lock (wallet)
      (lock-wallet wallet))
    nil))

;;; --- Backup / restore ---
;;;
;;; Core's backupwallet is sqlite3_backup_* over a single file. We store a
;;; LevelDB DIRECTORY per wallet, and copying a live LevelDB is unsafe in a
;;; way that fails SILENTLY: the newest writes live in the memtable and the
;;; current log, a background compaction rewrites MANIFEST/CURRENT while
;;; adding and unlinking .ldb files, and a copy that catches that window can
;;; open perfectly while missing whole key ranges. LevelDB (unlike RocksDB)
;;; has no checkpoint API to make the copy consistent.
;;;
;;; So we keep Core's SEMANTICS (the destination is a file; restore copies
;;; it into <walletdir>/<name>/) with the mechanism of Core's own
;;; `bitcoin-wallet dump` / `createfromdump`: a checksummed logical dump of
;;; every record, taken under the wallet lock through one ordered iterator.
;;; A torn write is then detected rather than silently restored, and the
;;; restore rebuilds a fresh database instead of inheriting source damage.

(alexandria:define-constant +wallet-dump-magic+ "BITCOIN_LISP_WALLET_DUMP"
  :test #'equal)

(defconstant +wallet-dump-version+ 1)

(defun %hex-encode (bytes)
  (string-downcase (bl.crypto:bytes-to-hex bytes)))

(defun %wallet-dump-lines (wallet)
  "The dump's header and record lines, in LevelDB key order."
  (list* (format nil "~A,~D" +wallet-dump-magic+ +wallet-dump-version+)
         (format nil "network,~(~A~)" (wallet-network wallet))
         "format,leveldb"
         (mapcar (lambda (record)
                   (format nil "~A,~A"
                           (%hex-encode (car record))
                           (%hex-encode (cdr record))))
                 (wallet-db-records (wallet-db wallet)))))

(defun %write-wallet-dump (wallet path)
  "Write WALLET's dump to PATH atomically. Caller holds the wallet lock.

The temp file differs from PATH in its NAME, never its TYPE. RENAME-FILE
merges the target with the source pathname (CLHS), so a temp that differs
only by type renames to ITSELF whenever the destination has no extension —
which would report a successful backup while leaving nothing at the path the
user asked for."
  (let ((temp (make-pathname :name (concatenate 'string
                                                (or (pathname-name path) "wallet")
                                                ".tmp")
                             :defaults path))
        (body (with-output-to-string (s)
                (dolist (line (%wallet-dump-lines wallet))
                  (write-string line s)
                  (write-char #\Newline s)))))
    (let ((checksum (bl.crypto:hash256
                     (flexi-streams:string-to-octets body
                                                     :external-format :latin-1))))
      (unwind-protect
           (progn
             (with-open-file (out temp :direction :output
                                       :element-type 'character
                                       :external-format :latin-1
                                       :if-exists :supersede
                                       :if-does-not-exist :create)
               (write-string body out)
               (format out "checksum,~A~%" (%hex-encode checksum))
               (finish-output out)
               ;; A backup that is only in the page cache is not a backup:
               ;; the rename can reach the disk before the contents do, so a
               ;; crash would leave a correctly-named, empty or torn file.
               (ignore-errors
                (sb-posix:fsync (sb-sys:fd-stream-fd out))))
             (rename-file temp path)
             ;; POSIX does not make the rename itself durable until the
             ;; containing directory is synced (storage/utxo.lisp does the
             ;; same for the same reason).
             (bl.store::fsync-directory path)
             (setf temp nil))
        ;; A failed dump must not leave a partial file that looks like a
        ;; backup (Core dump.cpp:104-106 removes its temp the same way).
        (when (and temp (probe-file temp))
          (ignore-errors (delete-file temp)))))
    t))

(defconstant +wallet-dump-max-lines+ 4000000
  "Refuse a restore source longer than this many lines.

The path is caller-supplied and only has to exist, so without a bound
`restorewallet` pointed at a character device or an enormous file reads
until the image dies. A real wallet dump is a few records per key plus one
line per transaction; four million lines is far beyond any of ours.")

(defun %parse-wallet-dump (path network)
  "The dump's (key . value) byte pairs, or NIL if PATH is not a valid dump
for NETWORK. Everything is verified — magic, version, network, format, hex,
and the checksum over the whole file — BEFORE the caller creates anything."
  (handler-case
      (let ((lines '()))
        (with-open-file (in path :direction :input
                                 :element-type 'character
                                 :external-format :latin-1)
          (loop for line = (read-line in nil nil)
                for count from 0
                while line
                do (when (>= count +wallet-dump-max-lines+)
                     (return-from %parse-wallet-dump nil))
                   (push line lines)))
        (setf lines (nreverse lines))
        ;; header(3) + checksum(1)
        (when (< (length lines) 4)
          (return-from %parse-wallet-dump nil))
        (let* ((checksum-line (car (last lines)))
               (body-lines (butlast lines))
               (body (with-output-to-string (s)
                       (dolist (line body-lines)
                         (write-string line s)
                         (write-char #\Newline s)))))
          (unless (and (> (length checksum-line) 9)
                       (string= "checksum," checksum-line :end2 9)
                       (equalp (bl.crypto:hex-to-bytes
                                (subseq checksum-line 9))
                               (bl.crypto:hash256
                                (flexi-streams:string-to-octets
                                 body :external-format :latin-1))))
            (return-from %parse-wallet-dump nil))
          (unless (and (string= (first body-lines)
                                (format nil "~A,~D" +wallet-dump-magic+
                                        +wallet-dump-version+))
                       ;; The network line is our application_id: Core keeps
                       ;; the network magic in the SQLite header and refuses
                       ;; a cross-network file, and a mainnet backup must
                       ;; not restore onto a testnet node.
                       (string= (second body-lines)
                                (format nil "network,~(~A~)" network))
                       (string= (third body-lines) "format,leveldb"))
            (return-from %parse-wallet-dump nil))
          (loop for line in (cdddr body-lines)
                for comma = (position #\, line)
                unless comma do (return-from %parse-wallet-dump nil)
                collect (cons (bl.crypto:hex-to-bytes
                               (subseq line 0 comma))
                              (bl.crypto:hex-to-bytes
                               (subseq line (1+ comma)))))))
    (error () nil)))

(defun %resolved-directory (path)
  "PATH's directory components, absolute and with every `.` and `..` segment
resolved away. Purely lexical, so it works for a path that does not exist
yet (the backup destination normally does not)."
  (let* ((absolute (uiop:ensure-absolute-pathname
                    (uiop:ensure-directory-pathname path)
                    *default-pathname-defaults*))
         (resolved '()))
    (dolist (component (pathname-directory absolute) (nreverse resolved))
      (cond ((eq component :up) (pop resolved))
            ((eq component :back) (pop resolved))
            ((equal component ".") nil)
            (t (push component resolved))))))

(defun %path-under-p (path directory)
  "T when PATH is DIRECTORY itself or lies beneath it.

Both sides are resolved first: a textual prefix test on the raw components
would let `<walletdir>/../../wallets/w` pass as \"not under the wallets
directory\" and then land right inside it."
  (let ((path-dir (%resolved-directory path))
        (base-dir (%resolved-directory directory)))
    (and (<= (length base-dir) (length path-dir))
         (equal base-dir (subseq path-dir 0 (length base-dir))))))

(bl.rpc:define-rpc "backupwallet" (node params)
  "Write a portable backup of the wallet to DESTINATION (Bitcoin Core
backupwallet). PARAMS: (destination). Returns null.

Works on a locked wallet: an encrypted wallet's backup holds only
ciphertext."
  (let ((wallet (wallet-for-request node))
        (destination (first params))
        (manager (node-wallet-manager-checked node)))
    (unless (stringp destination)
      (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "destination must be a string"))
    ;; Core's BlockUntilSyncedToCurrentChain equivalent: make sure the
    ;; best-block marker we are about to dump refers to the current tip.
    (%wallet-current-tip node)
    (handler-case
        (let ((path (uiop:parse-native-namestring destination)))
          (when (or (uiop:directory-exists-p path)
                    (%path-under-p path (wallets-directory manager)))
            (wallet-error "invalid backup destination"))
          (with-wallet-lock (wallet)
            (wallet-write-best-block wallet)
            (%write-wallet-dump wallet path)))
      (error (e)
        (bl:log-warn "backupwallet failed: ~A" e)
        (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-error+
                          :message "Error: Wallet backup failed!")))
    nil))

(defun %restore-cleanup (path existed)
  "Undo a failed restore: drop the database, and remove the directory only
if this call created it — a pre-existing directory may hold files that are
none of our business."
  (ignore-errors
   (bl.store:leveldb-destroy-db
    (namestring (uiop:ensure-directory-pathname path))))
  (unless existed
    (ignore-errors
     (when (and (uiop:directory-exists-p path)
                (null (uiop:directory-files path))
                (null (uiop:subdirectories path)))
       (uiop:delete-empty-directory path)))))

(bl.rpc:define-rpc "restorewallet" (node params)
  "Restore a wallet from a backup file and load it (Bitcoin Core
restorewallet). PARAMS: (wallet_name backup_file [load_on_startup])."
  (let* ((manager (node-wallet-manager-checked node))
         (name (first params))
         (backup-file (second params))
         (action (%load-on-startup-action (third params)))
         (warnings '()))
    (unless (and (stringp name) (plusp (length name)))
      (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "Wallet name cannot be empty"))
    ;; Core does no containment check here at all — AbsPathJoin lets
    ;; "../evil" escape the wallets directory. We do not copy that.
    (unless (%valid-wallet-name-p name)
      (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message (format nil "Invalid wallet name ~S" name)))
    (unless (and (stringp backup-file)
                 (probe-file (uiop:parse-native-namestring backup-file)))
      (error 'bl.rpc::rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "Backup file does not exist"))
    (let* ((path (wallet-directory manager name))
           (existed (and (uiop:directory-exists-p path) t)))
      ;; Core checks only that the destination is free (RestoreWallet,
      ;; wallet.cpp:486-492); a loaded wallet's directory exists too, so
      ;; this is also what a restore-over-a-live-wallet gets.
      (when (or (wallet-db-exists-p path)
                (gethash name (wallet-manager-wallets manager)))
        (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-already-exists+
                          :message (format nil "Failed to restore wallet. Database file exists in '~A'."
                                           (namestring path))))
      ;; Verify the whole dump BEFORE creating anything, so a bad file
      ;; leaves no directory behind.
      (let ((records (%parse-wallet-dump
                      (uiop:parse-native-namestring backup-file)
                      (wallet-manager-network manager))))
        (unless records
          (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-not-found+
                            :message (format nil "Wallet file verification failed. Failed to load database path '~A'. Data is not in recognized format."
                                             (namestring path))))
        (handler-case
            (let ((db (wallet-db-open path :create t)))
              (unwind-protect
                   ;; One batch: the restored database is either complete
                   ;; or absent, never half-written.
                   (bl.store:with-leveldb-writebatch (batch)
                     (dolist (record records)
                       (bl.store:leveldb-writebatch-put
                        batch (car record) (cdr record)))
                     (bl.store:leveldb-write db batch :sync t))
                (bl.store:leveldb-close db)))
          (error (e)
            (%restore-cleanup path existed)
            (bl:log-warn "restorewallet: writing ~A failed: ~A" name e)
            (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-error+
                              :message (format nil "Wallet loading failed. ~A" e)))))
      (handler-case
          (multiple-value-bind (wallet load-warnings)
              (%load-and-attach-wallet node manager name)
            (declare (ignore wallet))
            (setf warnings load-warnings))
        (bl.rpc::rpc-error (e)
          (%restore-cleanup path existed)
          (error e))
        (error (e)
          (%restore-cleanup path existed)
          (error 'bl.rpc::rpc-error :code bl.rpc::+rpc-wallet-error+
                            :message (format nil "Wallet loading failed. ~A" e))))
      (unless (update-wallet-setting (wallet-manager-data-directory manager)
                                     name action)
        (setf warnings (append warnings (list (%load-on-startup-warning action)))))
      (%push-warnings warnings `(("name" . ,name))))))
