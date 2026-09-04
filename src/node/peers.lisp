(in-package #:bitcoin-lisp)

;;;; Peer Management

;;;; Anchor connections (Bitcoin Core anchors.dat)
;;;;
;;;; On shutdown we persist a couple of currently-connected outbound peers and
;;;; reconnect to them first on the next start, BEFORE consulting DNS seeds.
;;;; This closes the across-restart eclipse window: a freshly-started node that
;;;; relied only on DNS seeds (or a poisoned addrman) could be fed an attacker's
;;;; peer set, but a known-good anchor it was just connected to cannot be
;;;; substituted by the attacker. (Core anchors are block-relay-only peers;
;;;; dedicated block-relay-only outbound slots are a separate follow-up — these
;;;; anchors are drawn from the regular outbound pool.)

(defconstant +max-anchors+ 2
  "How many outbound peers to persist as reconnection anchors (Core saves 2).")

(defconstant +anchors-magic-v1+ #x414e4331)  ; "ANC1" — bare IP strings, no port
(defconstant +anchors-magic-v2+ #x414e4332)  ; "ANC2" — network-typed + port

(defvar *pending-anchor-addresses* nil
  "Anchor dial candidates — (host-string . port) conses, port NIL meaning the
network default — loaded at startup and consumed (and cleared) by the first
connect-to-peers so they are attempted before DNS-seed candidates.")

(defun anchors-dat-path (data-directory)
  "Path to anchors.dat in DATA-DIRECTORY."
  (merge-pathnames "anchors.dat" data-directory))

(defun save-anchor-entries (path entries)
  "Write anchor ENTRIES — a list of (network bytes port) — to PATH in the v2
format: magic \"ANC2\", count byte, then per entry a BIP155-style net id,
length-prefixed address bytes and a big-endian port (crash-safe: temp +
fsync + atomic rename, CRC32-protected)."
  (bl.store:save-file-with-crc32
   path
   (lambda (stream)
     (loop for shift in '(24 16 8 0)
           do (write-byte (ldb (byte 8 shift) +anchors-magic-v2+) stream))
     (write-byte (length entries) stream)
     (dolist (e entries)
       (destructuring-bind (net bytes port) e
         (write-byte (bl.net:network-key-id net) stream)
         (write-byte (length bytes) stream)
         (write-sequence bytes stream)
         (write-byte (ldb (byte 8 8) port) stream)
         (write-byte (ldb (byte 8 0) port) stream))))))

(defun parse-anchor-entries (bytes)
  "Parse anchors.dat payload BYTES (CRC already verified) into a list of
(network bytes port). Reads the v2 network-typed format; a v1 file (bare IP
strings without port) is MIGRATED: each string is parsed to a typed address,
with the port NIL (caller substitutes the network default — all v1-era
anchors were dialed at the default port anyway). Unparseable v1 entries
(e.g. a hostname from addnode) are dropped. Returns NIL for unknown magic."
  (let ((end (- (length bytes) 4))              ; stay inside payload (before CRC)
        (magic (logior (ash (aref bytes 0) 24) (ash (aref bytes 1) 16)
                       (ash (aref bytes 2) 8) (aref bytes 3)))
        (entries '()))
    (cond
      ((= magic +anchors-magic-v2+)
       (let ((count (aref bytes 4)) (pos 5))
         (dotimes (i count)
           (when (< (+ pos 2) end)
             (let ((net (bl.net:key-id-network (aref bytes pos)))
                   (len (aref bytes (1+ pos))))
               (incf pos 2)
               (when (and net (<= (+ pos len 2) end))
                 (push (list net
                             (coerce (subseq bytes pos (+ pos len))
                                     '(simple-array (unsigned-byte 8) (*)))
                             (logior (ash (aref bytes (+ pos len)) 8)
                                     (aref bytes (+ pos len 1))))
                       entries))
               (incf pos (+ len 2)))))))
      ((= magic +anchors-magic-v1+)
       (let ((count (aref bytes 4)) (pos 5))
         (dotimes (i count)
           (when (< pos end)
             (let ((len (aref bytes pos)))
               (incf pos)
               (when (<= (+ pos len) end)
                 (multiple-value-bind (net addr-bytes)
                     (bl.net:parse-network-address
                      (map 'string #'code-char (subseq bytes pos (+ pos len))))
                   (when net
                     (push (list net addr-bytes nil) entries)))
                 (incf pos len)))))))
      (t (return-from parse-anchor-entries nil)))
    (nreverse entries)))

(defun save-anchors (node)
  "Persist up to +max-anchors+ currently-connected outbound peers to
anchors.dat in the network-typed v2 format (net + address + port)."
  (let* ((ready-outbound
           (remove-if-not
            (lambda (p) (and (not (bl.net:peer-inbound p))
                             (eq (bl.net:peer-state p) :ready)))
            (node-peers node)))
         ;; Prefer block-relay-only peers as anchors (Core anchors are
         ;; block-relay: an attacker who fed us a poisoned addrman can't
         ;; substitute a peer we were just block-relay-connected to). Fall back
         ;; to full-relay outbound if we have no block-relay peers.
         (block-relay (remove-if-not
                       (lambda (p) (eq (bl.net:peer-conn-type p)
                                       :block-relay))
                       ready-outbound))
         (ready (or block-relay ready-outbound))
         (default-port (network-port (node-network node)))
         (entries
           (loop for p in (subseq ready 0 (min +max-anchors+ (length ready)))
                 for (net bytes) = (multiple-value-list
                                    (bl.net:parse-network-address
                                     (bl.net:peer-address p)))
                 when net                        ; hostname peers (addnode) skipped
                   collect (list net bytes
                                 (let ((conn (bl.net:peer-connection p)))
                                   (if conn
                                       (bl.net:connection-port conn)
                                       default-port))))))
    (when entries
      (handler-case
          (save-anchor-entries (anchors-dat-path (node-data-directory node)) entries)
        (error (e) (log-warn "Failed to save anchors: ~A" e)))
      (log-info "Saved ~D anchor peer~:P" (length entries)))))

(defun load-anchors (node)
  "Read anchors.dat into *pending-anchor-addresses* — (host . port) dial
candidates, dialed at the STORED port (migrated v1 entries carry port NIL and
fall back to the network default) — so the next connect attempts them first.
Reading CONSUMES the file, as Core's ReadAnchors does (addrdb.cpp:234-246):
anchors are one-shot, so a crash loop cannot re-dial the same two block-relay
peers on every start and pin an already-eclipsed node to them. The next clean
shutdown rewrites it. Missing/corrupt file is ignored; a v1-era file migrates
(see parse-anchor-entries) and the next save rewrites it as v2. Only networks that
are dialable under the current config (dialable-network-p: onion needs a Tor
proxy, cjdns needs -cjdnsreachable) and reachable (-onlynet) become dial
candidates."
  (let* ((path (anchors-dat-path (node-data-directory node)))
         (bytes (bl.store:load-file-with-crc32 path 6)))
    ;; Unconditionally, parse failure included (Core ReadAnchors). A failure
    ;; here leaves the anchors in place, which silently restores the pinning
    ;; this prevents — so say so rather than swallowing it.
    (handler-case (delete-file path)
      (file-error () )
      (error (c) (log-debug "Could not consume ~A: ~A" path c)))
    (when bytes
      (setf *pending-anchor-addresses*
            (loop for (net addr-bytes port) in (parse-anchor-entries bytes)
                  when (and (bl.net:dialable-network-p net)
                            (bl.net:reachable-network-p net))
                    collect (cons (bl.net:network-address-to-string
                                   net addr-bytes)
                                  port)))
      (when *pending-anchor-addresses*
        (log-info "Loaded ~D anchor peer~:P for priority reconnection"
                  (length *pending-anchor-addresses*))))))

(defun %reachable-seed-addresses (addresses)
  "Keep only the seed-derived ADDRESSES (strings) we may actually dial.

An address LITERAL survives when -onlynet still permits its network. Seed
lists — DNS-seed results and the hardcoded fixed seeds — are clearnet by
construction, so under -onlynet=onion (or cjdns-only) dialing them is a direct
deanonymizing clearnet TCP connection. Core never hits this because seeds go
into addrman and every dial candidate is filtered by g_reachable_nets at
selection time (ThreadOpenConnections); we build the dial list directly, so the
filter has to happen here. The addrman branch above is already filtered by
select-dialable-address, and anchors by load-anchors.

A candidate parse-network-address cannot classify is a HOSTNAME, and survives
only when a SOCKS5 proxy is configured AND clearnet is reachable. Under -proxy
discover-peers deliberately returns the seed hostnames UNRESOLVED (protocol.lisp)
— resolving them locally would leak a plaintext DNS query outside the tunnel —
and make-tcp-connection hands each one to the proxy inside the SOCKS5 CONNECT
(ATYP DOMAINNAME, socks5.lisp) for the proxy to resolve. That mirrors Core's
'if (HaveNameProxy()) AddAddrFetch(seed)' (net.cpp:2356-2357): a proxied seed
stays dialable BY NAME. Dropping those unconditionally (this filter's behaviour
as first written) left a proxied node with a fresh datadir zero dial
candidates on mainnet/signet/testnet3 — they have hostname DNS seeds and no
fixed-seed list, so it could not bootstrap at all.

The clearnet conjunct keeps the -onlynet privacy guarantee closed HERE, not
merely upstream: a DNS seed answers with A/AAAA records, so a hostname
candidate is a clearnet candidate however it gets resolved. It cannot cost a
dial in any configuration apply-config-globals can produce, since an -onlynet
excluding IPv4 and IPv6 already soft-sets -dnsseed=0 (config.lisp, Core
init.cpp:835-844) so no hostname ever reaches this function, and with no proxy
discover-peers emits IP literals only.

Applies to SEED candidates only: manual -addnode/-connect targets are
deliberately exempt from -onlynet, matching Core."
  (let ((name-proxy-p
          (and bl.net:*proxy*
               (or (bl.net:reachable-network-p :ipv4)
                   (bl.net:reachable-network-p :ipv6))
               t)))
    (remove-if-not (lambda (addr)
                     (let ((net (bl.net:parse-network-address addr)))
                       (if net
                           (bl.net:reachable-network-p net)
                           name-proxy-p)))
                   addresses)))

(defun %diversity-counted-peer-p (peer)
  "T for the connection types that contribute to the outbound netgroup set —
Core's switch on pnode->m_conn_type in ThreadOpenConnections
(net.cpp:2657-2687): MANUAL, OUTBOUND_FULL_RELAY and BLOCK_RELAY insert a
group, and INBOUND, ADDR_FETCH, FEELER and PRIVATE_BROADCAST explicitly break
out contributing nothing.

The INBOUND case carries Core's reason verbatim: \"We currently don't take
inbound connections into account. Since they are free to make, an attacker
could make them to prevent us from connecting to certain peers.\" ADDR_FETCH
and FEELER are excluded as \"short-lived outbound connections [that] should
not affect how we select outbound peers from addrman\" — ours reach
NODE-PEERS through establish-outbound-peer's -seednode call, so the
conn-type test is doing real work and a plain not-inbound test would not.
Manual peers are typed :outbound-full-relay here and so are counted, which
is Core's MANUAL case."
  (and (not (bl.net:peer-inbound peer))
       (member (bl.net:peer-conn-type peer) '(:outbound-full-relay :block-relay))
       t))

(defun %outbound-netgroup-diversity (peers)
  "(VALUES NETGROUPS PRIVACY-COUNT) for PEERS — Core's
outbound_ipv46_peer_netgroups and outbound_privacy_network_peers, built in one
pass over m_nodes (net.cpp:2651-2688).

NETGROUPS is the set of /16 netgroups our ipv4/ipv6 outbound peers occupy; a
candidate whose group is in it is skipped (net.cpp:2825-2827). PRIVACY-COUNT is
how many outbound peers are on Tor/I2P/CJDNS: Core deliberately does NOT give
those a group, \"since our addrman-groups for these networks are random,
without relation to the route we take\", and counts them instead, where the
count feeds the addrman failure gate only.

This set used to be every peer's group, inbound included, which is the eclipse
primitive Core's comment names: inbound slots are free, so an attacker holding
114 of them across the /16s of our candidate list could veto every replacement
dial while our outbound peers died off. The neighbouring arithmetic
(COUNT-OUTBOUND-FULL-RELAY-PEERS) had already been fixed the same way; the
netgroup set had not."
  (let ((groups '())
        (privacy 0))
    (dolist (peer peers (values groups privacy))
      (when (%diversity-counted-peer-p peer)
        (let ((address (bl.net:peer-address peer)))
          (if (member (bl.net:parse-network-address address)
                      '(:torv3 :i2p :cjdns))
              (incf privacy)
              (let ((group (bl.net:ip-netgroup address)))
                (when group (pushnew group groups :test #'equal)))))))))

(defun %count-addrman-failures-p (netgroups privacy-count)
  "Core's count_failures (net.cpp:2884-2891): record addrman FAILURES only once
this node has at least min(m_max_automatic_connections - 1, 2) outbound
netgroups plus privacy-network peers.

Core's comment is the whole rationale: \"Don't record addrman failure attempts
when node is offline. This can be identified since all local network
connections (if any) belong in the same netgroup, and the size of
`outbound_ipv46_peer_netgroups` would only be 1.\" A link that is down, a
resumed laptop, or a node started before the network is, otherwise charges a
real failure to every address it cycles through; a few such episodes push
nAttempts past +ADDRMAN-RETRIES+ with no success recorded, at which point
addr-info-terrible-p is true for those entries — getaddr stops returning them,
they become preferred overwrite targets, and their GetChance collapses.

The threshold is stated against the automatic connection TOTAL, so it is
*MAX-AUTOMATIC-CONNECTIONS* here and not NODE-MAX-PEERS; for any -maxconnections
above 2 it is simply 2."
  (>= (+ (length netgroups) privacy-count)
      (min (1- *max-automatic-connections*) 2)))

(defun %record-dial-attempt (node host port count-failure)
  "Stamp an addrman dial attempt for HOST:PORT — Core CConnman::ConnectNode
calls addrman.Attempt() on EVERY dial, immediately after the attempt and before
the socket is examined (net.cpp:492-497).

We recorded attempts from exactly one place, the failure branch of
connect-to-peers, and that function runs only at startup and when the peer
count hits zero. Every steady-state dial — replace-disconnected-peers,
establish-outbound-peer (and so maintain-block-relay-peers), and the feeler —
recorded nothing, so nAttempts stayed 0 for addresses we had tried and failed
repeatedly. addrman's whole quality signal is that counter: without it the
selection cannot age out dead addresses, the feeler that exists to prove the
tried table cannot mark anything bad, and we keep re-dialing and re-gossiping
the same corpses. That is an eclipse-resistance and getaddr-hygiene loss, not a
crash.

Good() resets the counter on a successful VERSION, so stamping every dial does
not penalise addresses that work.

COUNT-FAILURE is Core's fCountFailure, and it is a REQUIRED argument for the
same reason Core makes it one of OpenNetworkConnection's parameters: only
ThreadOpenConnections ever passes true (%COUNT-ADDRMAN-FAILURES-P), and
every other call site — ADDR_FETCH/-seednode (net.cpp:2422), -connect MANUAL
(:2541), added nodes (:2986), addconnection (:1905), the reconnect queue
(:4157) — passes literal false. Attempt() stamps m_last_try either way; it is
only nAttempts, the counter addr-info-terrible-p and GetChance read, that
COUNT-FAILURE gates. Hard-coding it true charged a real failure to every
address a link-down node cycled through, and to manual targets that were
merely switched off, which Core never does.

Divergence: Core's Attempt() call is additionally guarded by
`!proxyConnectionFailed', so a dead SOCKS5 proxy blames nothing. We stamp
BEFORE the dial and make-tcp-connection reports a proxy failure and a target
failure the same way (NIL), so we have no signal to carry that guard; a whole
onion set behind a dead Tor proxy still accrues last_try stamps, and failures
too once the gate below is open."
  (let ((address-book (node-address-book node)))
    (when address-book
      (multiple-value-bind (net ip-bytes)
          (bl.net:parse-network-address host)
        (when net
          (ignore-errors
           (bl.net:address-book-attempt
            address-book ip-bytes port
            :count-failure count-failure :net net)))))))

(defun %seed-address-book-from-dns (node)
  "Query the DNS seeds and put what they return into the address book, the way
Core's ThreadDNSAddressSeed does (net.cpp:2340-2360).

Runs in its own thread so start-up is not blocked on DNS, which is also why
Core makes it a thread. Failures are logged and dropped: a node that cannot
reach a seed still has its address book, its -connect peers and its fixed
seeds."
  (let ((book (node-address-book node))
        ;; PEER-ADDRESS's PORT slot is an (unsigned-byte 16); a DNS seed
        ;; answers with bare addresses, so they take the network's default
        ;; port, exactly as Core's ThreadDNSAddressSeed does.
        (port (network-port (node-network node))))
    (when book
      (bt:make-thread
       (lambda ()
         (handler-case
             (let ((added 0))
               (dolist (addr (bl.net:discover-peers))
                 (multiple-value-bind (net ip-bytes)
                     (bl.net:parse-network-address addr)
                   (when (and net
                              (not (bl.net:address-book-lookup
                                    book ip-bytes port net)))
                     (when (bl.net:address-book-add
                            book
                            (bl.net:make-peer-address
                             :net net :ip ip-bytes :port port :services 0
                             :last-seen (bl.ser:get-unix-time)))
                       (incf added)))))
               (log-info "DNS seeds contributed ~D new address~:P" added))
           (error (e)
             (log-warn "DNS seeding failed: ~A" e))))
       :name "bitcoin-dnsseed-thread"))))

(defun %record-outbound-result (address-book addr port peer success
                                &key count-failure)
  "Record an outbound dial outcome for ADDR:PORT in ADDRESS-BOOK, adding the
entry if new (network-typed, so IPv6/onion/cjdns peers get addrman credit
too): SUCCESS => Good + Connected, failure => Attempt
(Core CConnman's addrman feedback in ConnectNode/OpenNetworkConnection).
Hostname dial targets (unparseable as addresses) are skipped.

COUNT-FAILURE is Core's fCountFailure and defaults to NIL, which is what every
OpenNetworkConnection call site but ThreadOpenConnections passes; only the
caller that is ThreadOpenConnections states it, from
%COUNT-ADDRMAN-FAILURES-P. It reaches the failure branch alone — a success
resets nAttempts to 0 anyway."
  (when address-book
    (multiple-value-bind (net ip-bytes)
        (bl.net:parse-network-address addr)
      (when net
        (unless (bl.net:address-book-lookup
                 address-book ip-bytes port net)
          (bl.net:address-book-add
           address-book
           (bl.net:make-peer-address
            :net net :ip ip-bytes :port port
            :services (if (and success peer)
                          (bl.net:peer-services peer)
                          0)
            :last-seen (bl.ser:get-unix-time))))
        (if success
            (progn
              (bl.net:address-book-good
               address-book ip-bytes port
               (bl.ser:get-unix-time) net)
              (bl.net:address-book-connected
               address-book ip-bytes port
               (bl.ser:get-unix-time) net))
            (bl.net:address-book-attempt
             address-book ip-bytes port
             :count-failure count-failure :net net))))))

(defun connect-to-peers (node max-peers &key (timeout 60) (min-peers 1))
  "Connect to Bitcoin network peers.
Uses address book for warm starts, falls back to DNS seeds. Dial candidates
are (host . port) conses (port NIL = network default): addrman picks and
anchors carry their STORED ports, DNS/fixed seeds the default. Onion default
port = chain default port (Core net.cpp:3395-3404 GetDefaultPort), so the
same fallback covers .onion candidates.
MAX-PEERS: Target number of peers to connect
TIMEOUT: Maximum seconds to spend connecting (default 60)
MIN-PEERS: Return early once we have at least this many peers (default 1)
Returns the number of peers connected."
  ;; setnetworkactive off: make no outbound connections.
  (unless (node-network-active node)
    (return-from connect-to-peers 0))
  ;; -connect: the only outbound peers are the specified ones, dialed by
  ;; connect-specified-nodes. Returning 0 here rather than dialing them makes
  ;; the two paths one path — the startup dial and the maintenance dial cannot
  ;; disagree about which targets are current.
  (unless (addrman-outgoing-enabled-p)
    (connect-specified-nodes node)
    (return-from connect-to-peers (length (node-peers node))))
  (let ((address-book (node-address-book node))
        (addresses '()))
    ;; Warm start: select peers from the addrman (new/tried buckets,
    ;; eclipse-resistant) rather than a single global score ranking.
    (when (and address-book
               (>= (bl.net:address-book-count address-book) 8))
      (bl.net:resolve-tried-collisions address-book)
      (log-info "Using peer address book (~D entries)..."
                (bl.net:address-book-count address-book))
      (let ((seen (make-hash-table :test 'equal))
            (picks '()))
        (dotimes (i (* max-peers 8))
          ;; select-dialable-address, never raw select: post-BIP155 the book
          ;; can hold records not dialable under the current config (torv3
          ;; without a Tor proxy, i2p always, cjdns without -cjdnsreachable).
          (let ((pa (bl.net:select-dialable-address address-book)))
            (when pa
              (let ((str (bl.net:peer-address-string pa))
                    (port (bl.net:peer-address-port pa)))
                (unless (gethash str seen)
                  (setf (gethash str seen) t)
                  (push (cons str (and (plusp port) port)) picks))))))
        (setf addresses (nreverse picks))))
    ;; ⚠️ The DNS query used to live HERE, gated on "not enough candidates". It
    ;; is now a start-up step that feeds the ADDRESS BOOK
    ;; (%SEED-ADDRESS-BOOK-FROM-DNS), which is Core's shape: ThreadDNSAddressSeed
    ;; runs with connman and is independent of how any one dial is going.
    ;;
    ;; -forcednsseed still belongs here, because it means "query even though the
    ;; address book looks full" — a statement about this decision, not about
    ;; start-up (Core DEFAULT_FORCEDNSSEED, net.h:97). It does NOT override
    ;; -dnsseed=0, the same precedence Core's thread has.
    (when (and *force-dns-seed* *dns-seed-enabled*)
      (log-info "Discovering peers from DNS seeds...")
      (let* ((dns-addrs (bl.net:discover-peers))
             (usable (%reachable-seed-addresses dns-addrs)))
        (log-info "Found ~D potential peers from DNS~:[~; (~:*~D dialable under -onlynet)~]"
                  (length dns-addrs)
                  (and (/= (length usable) (length dns-addrs)) (length usable)))
        (setf addresses (append addresses
                                (mapcar (lambda (a) (cons a nil)) usable)))
        (setf addresses (remove-duplicates addresses :key #'car :test #'string=))))

    ;; Fixed-seed fallback for testnet4: even after DNS, the candidate pool
    ;; may have only one /16 group (sprovoost.nl seed has been dark since
    ;; ~2026-05; wiz.biz returns its own /24 cluster only). Mirrors Bitcoin
    ;; Core's vFixedSeeds population in chainparams.cpp — used as a
    ;; last-resort source so we always have netgroup diversity available.
    (let ((fixed (bl.chain:chain-params-fixed-seeds
                  (bl.chain:find-chain-params (node-network node)))))
      (when (and fixed
                 ;; -fixedseeds=0 forbids the hardcoded fallback (Core
                 ;; net.cpp:2571-2572 "Fixed seeds are disabled").
                 *fixed-seeds-enabled*
                 (let ((groups (remove-duplicates
                                (remove nil (mapcar (lambda (c)
                                                      (bl.net:ip-netgroup
                                                       (car c)))
                                                    addresses))
                                :test #'string=)))
                   (< (length groups) 8)))
        (log-info "Merging ~A fixed-seed list (~D peers, ~D /16 groups)"
                  (node-network node) (length fixed)
                  (length (remove-duplicates (mapcar #'bl.net:ip-netgroup fixed)
                                             :test #'string=)))
        (setf addresses
              (remove-duplicates
               (append addresses
                       (mapcar (lambda (a) (cons a nil))
                               (%reachable-seed-addresses fixed)))
               :key #'car :test #'string=))))

    ;; Diversify by /16 netgroup so the first 8 connection attempts spread
    ;; across distinct operators (incident 2026-05-11: 8-of-8 peers were
    ;; from 103.165.192.x wiz.biz nodes — one stall stalled the whole
    ;; sync). Mirrors Bitcoin Core's addrman netgroup bucket selection
    ;; (netaddress.cpp CNetAddr::GetGroup).
    (setf addresses (bl.net:diversify-by-netgroup addresses
                                                                   :key #'car))

    ;; Anchors first (Core anchors.dat): reconnect to the peers we persisted at
    ;; last shutdown before any DNS/addrman candidate, then consume them so
    ;; later reconnect cycles use the normal pool.
    (when *pending-anchor-addresses*
      (setf addresses (remove-duplicates (append *pending-anchor-addresses* addresses)
                                         :key #'car :test #'string= :from-end t))
      (setf *pending-anchor-addresses* nil))

    (log-info "~D candidate peers available" (length addresses))

    ;; Store discovered addresses for reconnection
    (setf (node-known-addresses node) addresses)

    (let ((connected 0)
          (start-time (get-internal-real-time))
          (timeout-ticks (* timeout internal-time-units-per-second)))
      (dolist (candidate (node-known-addresses node))
        ;; Stop if we have enough peers
        (when (>= connected max-peers)
          (return))

        ;; Check timeout - but only exit early if we have minimum peers
        (when (and (>= connected min-peers)
                   (> (- (get-internal-real-time) start-time) timeout-ticks))
          (log-info "Connection timeout reached with ~D peers" connected)
          (return))

        (let* ((addr (car candidate))
               (dial-port (or (cdr candidate) (network-port (node-network node)))))
          (log-debug "Trying to connect to ~A..." addr)
          (handler-case
              (let ((peer (bl.net:connect-peer addr dial-port)))
                (when peer
                  (setf (bl.net:peer-address peer) addr)
                  (log-info "Connected to ~A" addr)
                  ;; Perform handshake
                  (when (bl.net:perform-handshake peer :near-tip (bl.net:near-tip-p (node-chain-state node)))
                    (log-info "Handshake complete with ~A (~A, height ~D)"
                              addr
                              (bl.net:peer-user-agent peer)
                              (bl.net:peer-start-height peer))
                    ;; Send feature negotiation messages
                    (bl.net:send-post-handshake-messages peer)
                    ;; Record success in address book (add if not present)
                    (%record-outbound-result address-book addr dial-port peer t)
                    ;; Send compact block negotiation (BIP 152)
                    (bl.net:send-compact-block-negotiation peer)
                    (bt:with-recursive-lock-held ((node-lock node))
                      (push peer (node-peers node)))
                    (incf connected))
                  (unless (eq (bl.net:peer-state peer) :ready)
                    (bl.net:disconnect-peer peer))))
            (error (c)
              (log-debug "Failed to connect to ~A: ~A" addr c)
              ;; Record failure in address book (add if not present). This loop
              ;; IS Core's ThreadOpenConnections for the initial fill, so the
              ;; failure counts only once the node looks online — recomputed
              ;; per candidate, as Core rescans m_nodes on every iteration.
              (multiple-value-bind (groups privacy)
                  (%outbound-netgroup-diversity (node-peers node))
                (%record-outbound-result
                 address-book addr dial-port nil nil
                 :count-failure (%count-addrman-failures-p groups privacy)))))))

      (log-info "Connected to ~D peer~:P" connected)
      connected)))

;;;; Peer Health and Reconnection

(defun check-peers-health (node)
  "Check health of all peers. Disconnect unresponsive ones.
Also checks compact block reconstruction timeouts (BIP 152)."
  (let ((to-disconnect '()))
    (dolist (peer (node-peers node))
      ;; Both checks below can WRITE (ping, compact-block getdata); a peer
      ;; that FIN'd since the last drain raises stream-error from that
      ;; write. Fold any error into :disconnect instead of letting it
      ;; escape — this runs on the sync thread, whose outer handler-case
      ;; would otherwise end the thread (2026-05-09 incident pattern).
      (handler-case
          (progn
            ;; Check compact block timeout
            (bl.net:check-compact-block-timeout peer)
            ;; Check ping/pong health
            (let ((status (bl.net:check-peer-health peer)))
              (when (eq status :disconnect)
                (push peer to-disconnect))))
        (error () (push peer to-disconnect))))
    (dolist (peer to-disconnect)
      (log-warn "Disconnecting unresponsive peer ~A"
                (bl.net:peer-address peer))
      (handler-case
          (bl.net:disconnect-peer peer)
        (error (c) (declare (ignore c))))
      (bt:with-recursive-lock-held ((node-lock node))
        (setf (node-peers node) (remove peer (node-peers node)))))
    (length to-disconnect)))

(defun outbound-full-relay-peer-p (peer)
  "T iff PEER is a ready outbound full-relay connection — the only kind that
counts toward the outbound full-relay target (Core CNode::IsFullOutboundConn:
m_conn_type == OUTBOUND_FULL_RELAY, which is never inbound). Inbound peers
and block-relay/feeler outbound peers are deliberately excluded."
  (and (eq (bl.net:peer-state peer) :ready)
       (not (bl.net:peer-inbound peer))
       (eq (bl.net:peer-conn-type peer) :outbound-full-relay)))

(defun count-outbound-full-relay-peers (peers)
  "Count ready outbound full-relay peers among PEERS (Core nOutboundFullRelay).
Inbound connections are excluded so an attacker filling our inbound slots
cannot suppress replacement outbound dials (eclipse-attack prevention)."
  (count-if #'outbound-full-relay-peer-p peers))

(defconstant +pow-target-spacing-seconds+ 600
  "Core consensus.nPowTargetSpacing. It is 10*60 on EVERY network Core ships —
mainnet, testnet3, testnet4, signet and regtest (kernel/chainparams.cpp:98,
229, 336, 486, 577) — so the stale-tip threshold below needs no per-network
case, and regtest is testable against it without a special fixture.")

(defconstant +stale-tip-age-seconds+ (* 3 +pow-target-spacing-seconds+)
  "Core TipMayBeStale's threshold: nPowTargetSpacing * 3 = 1800s
(net_processing.cpp:1339). The factor is THREE. Earlier revisions of
docs/eclipse-resistance-plan.md wrote it as `30 * 600 = 1800s' — right product,
wrong factor — which lands on 18000s, five hours, if copied literally. Written
as the multiplication rather than the number so the two can never drift apart.")

(defconstant +stale-tip-check-interval-seconds+ 600
  "Core STALE_CHECK_INTERVAL (net_processing.cpp:108). This gates the stale-tip
half ALONE and is nested inside the 45s sweep — the two cadences are different
and both real. Checking staleness every 45s instead would re-evaluate a
1800s-old condition forty times before it could change.")

(defvar *last-stale-tip-check* 0
  "Unix time of the last stale-tip evaluation (Core m_stale_tip_check_time).")

(defvar *try-new-outbound-peer* nil
  "Core CConnman::m_try_another_outbound_peer. While true the dialer may open
ONE full-relay connection beyond node-max-peers.

Note what this does NOT do: it does not raise the eviction target. Core's
GetExtraFullOutboundCount still measures against the unraised
m_max_outbound_full_relay (net.cpp:2473), so the moment the extra peer connects
the rotation sees one peer too many and drops the stalest. That is the whole
mechanism — the extra slot buys a REPLACEMENT, not a bigger peer set. Raising
both targets together, the intuitive reading, would make the extra peer
permanent and the rotation would never fire at all.")

(defun outbound-dial-budget (node)
  "How many outbound full-relay connections the DIALER may hold: node-max-peers,
plus one while the stale-tip extra slot is granted.

Core opens that extra peer from a SEPARATE branch of ThreadOpenConnections
(net.cpp:2722), reached only after the normal full-relay and block-relay
targets are already satisfied — so it is exactly one connection more than we
would otherwise dial, and only while the tip looks stuck.

The eviction target is deliberately NOT this number (see
consider-outbound-evictions): Core's GetExtraFullOutboundCount measures against
the unraised maximum, so the extra peer is immediately one too many and the
rotation drops the stalest. Dialing budget and eviction budget differing by one
IS the mechanism; making them agree would turn a replacement into permanent
growth and silence the rotation."
  (+ (node-max-peers node) (if *try-new-outbound-peer* 1 0)))

(defun tip-may-be-stale-p (node)
  "Core PeerManagerImpl::TipMayBeStale (net_processing.cpp:1332): our tip has
not advanced in +STALE-TIP-AGE-SECONDS+ and no block is in flight from anyone.

The elapsed time is computed as a DIFFERENCE within get-node-time, never
by converting an epoch. node-last-tip-advance-time is universal time while
every other timer in this subsystem is unix seconds, and the plan records a
~2.2e9-second error from feeding one clock's value to the other. A difference
is epoch-independent, so there is nothing here to get wrong.

A node whose tip has never advanced stamps the clock and reports fresh, as
Core does for m_last_tip_update == 0 — otherwise every node would declare
itself eclipsed the moment it started."
  (let ((last (node-last-tip-advance-time node)))
    (cond ((not (plusp last))
           (setf (node-last-tip-advance-time node) (bl.ser:get-node-time))
           nil)
          (t (and (> (- (bl.ser:get-node-time) last) +stale-tip-age-seconds+)
                  (not (bl.net:any-blocks-in-flight-p)))))))

(defun check-for-stale-tip (node now)
  "Core's stale-tip half of CheckForStaleTipAndEvictPeers (:5468-5479), on its
own 10-minute timer. Sets or clears the extra-outbound permission.

The CLEAR is not optional and is the half that is easy to omit: without it the
first stale episode raises the dialing budget permanently, and the rotation —
which measures against the unraised target — then spends every 45s sweep
evicting a peer we just dialled. The feature would present as steady outbound
churn with no stale tip in sight.

Core guards this with three conditions; we carry one. GetNetworkActive is
node-network-active below. GetUseAddrmanOutgoing has no counterpart because we
have no -connect option — if one is ever added, it must gate this, or a node
pinned to a fixed peer list would start dialling addrman peers behind the
operator's back. LoadingBlocks likewise has no counterpart; in its place the
in-flight condition inside tip-may-be-stale-p keeps a node that is actively
fetching from calling its own tip stale."
  (when (> now *last-stale-tip-check*)
    (setf *last-stale-tip-check* (+ now +stale-tip-check-interval-seconds+))
    (cond ((and (node-network-active node)
                (tip-may-be-stale-p node))
           (unless *try-new-outbound-peer*
             (log-info "Potential stale tip detected (no advance in ~Ds); \
allowing one extra outbound peer"
                       (- (bl.ser:get-node-time) (node-last-tip-advance-time node))))
           (setf *try-new-outbound-peer* t))
          (*try-new-outbound-peer*
           (log-info "Tip is advancing again; releasing the extra outbound slot")
           (setf *try-new-outbound-peer* nil)))))

(defun replace-disconnected-peers (node)
  "Replace disconnected peers to maintain target peer count.
Returns the number of new peers connected."
  ;; Reap disconnected peers first — this also cleans up peers that
  ;; setnetworkactive dropped, even while networking stays disabled.
  (bt:with-recursive-lock-held ((node-lock node))
    (setf (node-peers node)
          (remove-if (lambda (p)
                       (eq (bl.net:peer-state p) :disconnected))
                     (node-peers node))))
  ;; setnetworkactive off: don't dial replacements.
  (unless (node-network-active node)
    (return-from replace-disconnected-peers 0))
  ;; -connect: this node picks no peers of its own. The reap above still runs —
  ;; a dead -connect peer must leave the list so connect-specified-nodes redials
  ;; it — but nothing here chooses a replacement from the address book.
  (unless (addrman-outgoing-enabled-p)
    (return-from replace-disconnected-peers 0))
  ;; Count ONLY outbound full-relay peers toward the outbound target — never
  ;; inbound, never block-relay/feeler. Core's ThreadOpenConnections counts
  ;; nOutboundFullRelay via IsFullOutboundConn() (net.cpp:2648-2657,2718) and
  ;; explicitly keeps inbound out of the arithmetic: inbound connections are
  ;; free for an attacker to make, so letting them satisfy the outbound
  ;; target is an eclipse primitive — 8 attacker inbounds previously
  ;; suppressed dialing any honest outbound replacement here. The inbound
  ;; population has its own separate cap (*max-inbound-connections*, enforced at
  ;; merge time in merge-inbound-peers). Block-relay-only peers are a
  ;; separate additive pool maintained by maintain-block-relay-peers (Core
  ;; keeps m_max_outbound_block_relay distinct from
  ;; m_max_outbound_full_relay); folding them in here would let 2 idle
  ;; block-relay slots starve replacement of a dropped full-relay peer.
  ;; (Known simplification vs Core: addnode peers are typed
  ;; :outbound-full-relay in our code, so they do count here, whereas Core's
  ;; MANUAL connections are additive.)
  (let* ((active-count (count-outbound-full-relay-peers (node-peers node)))
         (needed (- (outbound-dial-budget node) active-count)))
    (when (<= needed 0)
      (return-from replace-disconnected-peers 0))

    ;; Addresses already in use, and the netgroups our OUTBOUND peers hold.
    ;;
    ;; The two lists are deliberately different populations, and Core draws the
    ;; same line: AlreadyConnectedToAddress (net.cpp:347-351, consulted from
    ;; OpenNetworkConnection) compares against every node, inbound included,
    ;; because a second connection to one address is pointless either way —
    ;; while outbound_ipv46_peer_netgroups is built only from MANUAL /
    ;; OUTBOUND_FULL_RELAY / BLOCK_RELAY peers. Folding inbound peers into the
    ;; netgroup set, which this did, is the primitive Core's own comment names:
    ;; inbound slots are free to fill, so an attacker spread across the /16s of
    ;; node-known-addresses (a candidate list built once, at start-up) could
    ;; veto every replacement dial and watch our outbound set drain away.
    (let* ((peers (node-peers node))
           (used-addrs (mapcar #'bl.net:peer-address peers))
           (connected 0))
      (multiple-value-bind (used-groups privacy-peers)
          (%outbound-netgroup-diversity peers)
        ;; Core ThreadOpenConnections skips a candidate whose /16 netgroup
        ;; already holds an outbound peer (net.cpp:2825-2827). connect-to-peers
        ;; spreads the INITIAL set, but replacements had no netgroup test at
        ;; all, so hours of churn could concentrate the outbound set in one
        ;; group — half of an eclipse's preconditions.
        (dolist (candidate (node-known-addresses node))
          ;; Stop attempting new connect+handshake cycles the moment shutdown is
          ;; requested — each one can otherwise block (connect timeout + handshake
          ;; read) and delay the sync thread reaching its node-running checkpoint.
          (when (or (>= connected needed)
                    (bl.net:ibd-stop-requested-p))
            (return))
          (let ((addr (car candidate)))
            (unless (or (member addr used-addrs :test #'string=)
                        (let ((g (bl.net:ip-netgroup addr)))
                          (and g (member g used-groups :test #'equal))))
              (handler-case
                  (let* ((dial-port (or (cdr candidate)
                                        (network-port (node-network node))))
                         (peer (progn
                                 (%record-dial-attempt
                                  node addr dial-port
                                  (%count-addrman-failures-p used-groups
                                                             privacy-peers))
                                 (bl.net:connect-peer addr dial-port))))
                    (when peer
                      (setf (bl.net:peer-address peer) addr)
                      (when (bl.net:perform-handshake peer :near-tip (bl.net:near-tip-p (node-chain-state node)))
                        (log-info "Replacement peer connected: ~A" addr)
                        ;; Send feature negotiation messages
                        (bl.net:send-post-handshake-messages peer)
                        ;; Send compact block negotiation (BIP 152)
                        (bl.net:send-compact-block-negotiation peer)
                        (bt:with-recursive-lock-held ((node-lock node))
                          (push peer (node-peers node)))
                        ;; Core rebuilds both accumulators from m_nodes on
                        ;; every iteration, so the peer just added occupies its
                        ;; group for the rest of this refill; without carrying
                        ;; it forward a single pass could fill several outbound
                        ;; slots from one /16.
                        (multiple-value-setq (used-groups privacy-peers)
                          (%outbound-netgroup-diversity (node-peers node)))
                        (push addr used-addrs)
                        (incf connected))
                      (unless (eq (bl.net:peer-state peer) :ready)
                        (bl.net:disconnect-peer peer))))
                (error (c)
                  (declare (ignore c))))))))
      connected)))

;;;; Manually-added peers (addnode)

(defun parse-node-endpoint (node spec)
  "Split an addnode SPEC into (values host port). Accepts \"host\",
\"host:port\", and \"[ipv6]:port\"; bare or bracketless addresses default to the
network's P2P port. A trailing :port is only honored when it is all digits, so a
bare IPv6 address (which contains colons) is treated as host-only."
  (let ((default-port (network-port (node-network node))))
    (cond
      ;; [ipv6]:port  or  [ipv6]
      ((and (plusp (length spec)) (char= (char spec 0) #\[))
       (let ((close (position #\] spec)))
         (if close
             (let ((host (subseq spec 1 close))
                   (rest (subseq spec (1+ close))))
               (if (and (plusp (length rest)) (char= (char rest 0) #\:)
                        (plusp (length (subseq rest 1)))
                        (every #'digit-char-p (subseq rest 1)))
                   (values host (parse-integer rest :start 1))
                   (values host default-port)))
             (values spec default-port))))
      (t
       (let ((colon (position #\: spec :from-end t)))
         (if (and colon
                  (< (1+ colon) (length spec))
                  (every #'digit-char-p (subseq spec (1+ colon)))
                  ;; A single colon => host:port; multiple => bare IPv6.
                  (= colon (position #\: spec)))
             (values (subseq spec 0 colon) (parse-integer spec :start (1+ colon)))
             (values spec default-port)))))))

(defconstant +behind-retry-seconds+ 5
  "Seconds the sync loop's between-pass wait runs before giving up on the rest
of its 30-second cycle WHEN we hold headers above our own tip.

Not a poll interval — the wait already ends immediately on a new header
announcement. This covers the other order: headers that arrived during the sync
pass itself, where there is known work and nobody left to announce it. Bounded
rather than immediate so a chain no peer will serve retries on a timer instead
of spinning, which is the same reason the download loop has a no-progress
yield.")

(defun peer-connected-to-host-p (node host)
  "T if a peer at address HOST is currently in the node's peer list, ignoring
ports (Core AlreadyConnectedToAddress, net.cpp:347-351).

This is the guard for dials with NO destination string — the ones sourced from
addrman — which is the only place Core applies it. A dial that names a
destination uses PEER-CONNECTED-TO-ENDPOINT-P instead; see there for why the
difference is not cosmetic."
  (bt:with-recursive-lock-held ((node-lock node))
    (and (find host (node-peers node)
               :key #'bl.net:peer-address :test #'string=)
         t)))

(defun peer-connected-to-endpoint-p (node host port)
  "T if a peer at HOST:PORT is currently in the node's peer list (Core
AlreadyConnectedToHost, net.cpp:335-339).

The guard for every dial that names a destination: -addnode, `addnode onetry`,
-connect, -seednode. Core compares the full destination against each peer's
m_addr_name, and an INBOUND peer's name carries the ephemeral source port, so
an inbound connection from a host never blocks an outbound dial to it. Ours has
the same property for the same reason: an accepted connection records port 0
while a dialed one records the port it dialed.

Matching on HOST ALONE — which this used to do — is wrong wherever two peers
can share an address, and on regtest EVERY node is 127.0.0.1. One connection to
loopback then blocked every other, so a node could never hold more than one
connection to the local machine: the second `connect_nodes` in any Core
functional test found no new peer and timed out. Nothing looked wrong from
inside the node, which had simply been asked to dial a host it was already
talking to."
  (bt:with-recursive-lock-held ((node-lock node))
    (and (find-if (lambda (p)
                    (let ((conn (bl.net:peer-connection p)))
                      (and conn
                           (string= host (bl.net:connection-host conn))
                           (eql port (bl.net:connection-port conn)))))
                  (node-peers node))
         t)))

(defun establish-outbound-peer (node host port &key (conn-type :outbound-full-relay)
                                                    manual count-failure)
  "Full outbound connect + handshake to HOST:PORT, pushing the ready peer onto
node-peers. CONN-TYPE (:outbound-full-relay or :block-relay) sets the peer's
connection type; MANUAL tags an operator-pinned (-addnode / addnode onetry)
peer, Core's ConnectionType::MANUAL — set BEFORE the handshake, because the
VERSION-time services gate exempts manual peers (Core ExpectServicesFromConn)
and connect-added-nodes redials a missing added node every ~30 s, so gating one
would loop forever. Returns the peer or NIL. MUST run on the sync thread so
node-peers stays single-writer. No-op when networking is disabled.

COUNT-FAILURE defaults to NIL, and every caller that names a destination — the
-seednode addr-fetch, -connect, -addnode, `addnode onetry' and the
addconnection test RPC — leaves it there, because Core passes literal false at
each of those OpenNetworkConnection sites (net.cpp:2422, 2541, 2986, 1905): a
manual target that is merely switched off must not have addrman failures
charged against it. MAINTAIN-BLOCK-RELAY-PEERS is the one caller drawing from
addrman on its own initiative, i.e. the one that is ThreadOpenConnections, and
it passes %COUNT-ADDRMAN-FAILURES-P."
  (when (node-network-active node)
    (handler-case
        (let ((peer (progn (%record-dial-attempt node host port count-failure)
                           (bl.net:connect-peer host port))))
          (when peer
            (setf (bl.net:peer-address peer) host)
            (when manual (setf (bl.net:peer-manual peer) t))
            (if (bl.net:perform-handshake peer :conn-type conn-type
                                                        :near-tip (bl.net:near-tip-p (node-chain-state node)))
                (progn
                  (bl.net:send-post-handshake-messages peer)
                  (bl.net:send-compact-block-negotiation peer)
                  (bt:with-recursive-lock-held ((node-lock node))
                    (push peer (node-peers node)))
                  (log-info "Added-node peer connected: ~A" host)
                  peer)
                (progn (bl.net:disconnect-peer peer) nil))))
      (error (c)
        (log-debug "Added-node connect to ~A:~D failed: ~A" host port c)
        nil))))

(defun connect-seed-nodes (node)
  "Dial each -seednode once as an addr-fetch peer (Core ProcessAddrFetch,
net.cpp). The handshake already sends GETADDR for any non-block-relay outbound
peer, so the fetch needs no extra message; the peer disconnects itself from the
addr handler once it answers.

Skipped entirely when -connect is in force, which is Core's behaviour by
construction: ThreadOpenConnections takes the specified-addresses branch (or is
never started) and never reaches the seed queue."
  (when (and (node-network-active node) (addrman-outgoing-enabled-p) *seed-nodes*)
    (dolist (spec *seed-nodes*)
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-endpoint-p node host port)
          (log-info "Fetching addresses from -seednode ~A" spec)
          (establish-outbound-peer node host port :conn-type :addr-fetch))))))

(defun connect-specified-nodes (node)
  "Keep every -connect target connected (Core ThreadOpenConnections' first
branch, net.cpp: MANUAL connections dialed in a loop for as long as the node
runs). Distinct from connect-added-nodes only in which list it walks."
  (when (node-network-active node)
    (dolist (spec *connect-nodes*)
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-endpoint-p node host port)
          (establish-outbound-peer node host port :manual t))))))

(defun connect-added-nodes (node)
  "Service addnode requests on the sync thread: drain one-shot \"onetry\" dials,
then keep every \"add\" peer connected. Honors network-active."
  (when (node-network-active node)
    ;; One-shot onetry dials (Core addnode onetry).
    (let ((onetry (bt:with-recursive-lock-held ((node-lock node))
                    (prog1 (node-pending-onetry node)
                      (setf (node-pending-onetry node) nil)))))
      (dolist (spec onetry)
        (multiple-value-bind (host port) (parse-node-endpoint node spec)
          (unless (peer-connected-to-endpoint-p node host port)
            (establish-outbound-peer node host port :manual t)))))
    ;; addconnection (regtest testing RPC): one dial per request, of the
    ;; connection TYPE the caller named — which is the whole point of the RPC,
    ;; since a test cannot otherwise ask for a block-relay or feeler slot.
    (let ((queued (bt:with-recursive-lock-held ((node-lock node))
                    (prog1 (nreverse *pending-test-connections*)
                      (setf *pending-test-connections* nil)))))
      (dolist (request queued)
        (multiple-value-bind (host port) (parse-node-endpoint node (car request))
          (establish-outbound-peer node host port :conn-type (cdr request)))))
    ;; Maintain persistent added-node connections.
    (dolist (spec (node-added-nodes node))
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-endpoint-p node host port)
          (establish-outbound-peer node host port :manual t))))))

(defconstant +target-block-relay-peers+ 2
  "Dedicated block-relay-only outbound slots (Bitcoin Core opens 2). They carry
blocks/headers but no tx relay -- anti-partition insurance and the source of
reconnection anchors.")

(defun automatic-inbound-capacity (max-connections max-outbound-full-relay)
  "Core CConnman::Init (net.h:1110-1113): inbound capacity is the automatic
connection total less the automatic outbound slots — MAX-OUTBOUND-FULL-RELAY,
the block-relay-only slots (clamped to what remains, as Core clamps them) and
one feeler — never negative. MAX-OUTBOUND-FULL-RELAY is our :max-peers, which
is this node's m_max_outbound_full_relay and is deliberately NOT clamped to
Core's min(8, total): it is an operator knob here (run-node.sh sets 16)."
  (let* ((block-relay (max 0 (min +target-block-relay-peers+
                                  (- max-connections max-outbound-full-relay))))
         (feeler 1))
    (max 0 (- max-connections max-outbound-full-relay block-relay feeler))))

(defconstant +feeler-interval-seconds+ 120
  "Minimum spacing between feeler probes (Core FEELER_INTERVAL averages ~2 min).")

(defvar *last-feeler-time* 0
  "GET-NODE-TIME of the last feeler attempt, for rate-limiting.")

(defun peers-of-conn-type (node type)
  "Count current peers whose connection type is TYPE."
  (bt:with-recursive-lock-held ((node-lock node))
    (count type (node-peers node)
           :key #'bl.net:peer-conn-type)))

(defun %addrman-pick-unconnected (node &key new-only)
  "Pick an addrman address (as (values host port)) we're not already connected
to, or NIL; PORT is NIL when the record has none stored (caller substitutes
the network default). NEW-ONLY restricts to the 'new' table (for feelers).
Goes through select-dialable-address so automatic slots (block-relay,
feelers) only ever draw records dialable under the current config (torv3
needs a Tor proxy, cjdns needs -cjdnsreachable, i2p never)."
  (let ((ab (node-address-book node)))
    (when ab
      (dotimes (_ 20)
        (let ((pa (bl.net:select-dialable-address ab :new-only new-only)))
          (when pa
            (let ((host (bl.net:peer-address-string pa))
                  (port (bl.net:peer-address-port pa)))
              (unless (peer-connected-to-host-p node host)
                (return-from %addrman-pick-unconnected
                  (values host (and (plusp port) port)))))))))))

(defun maintain-block-relay-peers (node)
  "Ensure up to +target-block-relay-peers+ block-relay-only outbound peers.
Each carries blocks/headers only (relay=0), never tx relay."
  (when (and (node-network-active node) (node-address-book node)
             (addrman-outgoing-enabled-p))
    (loop while (< (peers-of-conn-type node :block-relay) +target-block-relay-peers+)
          do (multiple-value-bind (ip port) (%addrman-pick-unconnected node)
               (unless (and ip
                            (multiple-value-bind (groups privacy)
                                (%outbound-netgroup-diversity (node-peers node))
                              ;; The one establish-outbound-peer caller that is
                              ;; ThreadOpenConnections: nobody named this
                              ;; destination, addrman chose it.
                              (establish-outbound-peer
                               node ip (or port (network-port (node-network node)))
                               :conn-type :block-relay
                               :count-failure (%count-addrman-failures-p
                                               groups privacy))))
                 ;; No candidate, or the connect failed: stop trying this cycle.
                 (return))
               (log-info "Opened block-relay-only peer ~A" ip)))))

(defun do-feeler-connection (node host port count-failure)
  "Open a short-lived feeler connection: connect, handshake, and on success mark
the address good (promoting it new -> tried). Always disconnects afterward --
feelers exist only to validate addrman's tried table (Core anti-eclipse), never
to join the peer set.

COUNT-FAILURE is Core's fCountFailure: a feeler leaves ThreadOpenConnections
through the same OpenNetworkConnection call as any other automatic dial
(net.cpp:2891), so it is gated on the same online test and never hard-coded."
  (handler-case
      (let ((peer (progn (%record-dial-attempt node host port count-failure)
                         (bl.net:connect-peer host port))))
        (when peer
          (setf (bl.net:peer-address peer) host)
          (when (bl.net:perform-handshake peer :conn-type :feeler)
            (multiple-value-bind (net ip-bytes)
                (bl.net:parse-network-address host)
              (when net
                (bl.net:address-book-good
                 (node-address-book node) ip-bytes port
                 (bl.ser:get-unix-time) net)))
            (log-debug "Feeler validated ~A (new -> tried)" host))
          (bl.net:disconnect-peer peer)))
    (error (c)
      (log-debug "Feeler to ~A:~D failed: ~A" host port c))))

(defun maybe-do-feeler (node)
  "Rate-limited feeler probe. Core ThreadOpenConnections (net.cpp:2796-2812)
spends the feeler on a tried-table COLLISION first — testing the incumbent
before resolve-tried-collisions may evict it — and only otherwise validates a
'new' address into 'tried'. An incumbent we are already connected to needs no
probe: mark it good, which resolves the collision in its favour, and spend the
feeler on the new table instead."
  (let ((now (bl.ser:get-node-time)))
    (when (and (node-network-active node) (node-address-book node)
               (addrman-outgoing-enabled-p)
               (>= (- now *last-feeler-time*) +feeler-interval-seconds+))
      (setf *last-feeler-time* now)
      (let* ((book (node-address-book node))
             (incumbent (bl.net:select-tried-collision book))
             (host (and incumbent
                        (bl.net:peer-address-string incumbent))))
        (when (and host (peer-connected-to-host-p node host))
          (bl.net:address-book-good
           book (bl.net:peer-address-ip incumbent)
           (bl.net:peer-address-port incumbent)
           (bl.ser:get-unix-time)
           (bl.net:peer-address-network incumbent))
          (setf host nil))
        (multiple-value-bind (ip port)
            (if host
                (values host (let ((p (bl.net:peer-address-port incumbent)))
                               (and (plusp p) p)))
                (%addrman-pick-unconnected node :new-only t))
          (when ip
            (multiple-value-bind (groups privacy)
                (%outbound-netgroup-diversity (node-peers node))
              (do-feeler-connection
                  node ip (or port (network-port (node-network node)))
                (%count-addrman-failures-p groups privacy)))))))))

(defvar *last-chain-sync-check* 0
  "Unix time of the last chain-sync eviction sweep. Node-scoped, NOT local to
run-ibd: run-ibd is re-entered on every outer sync cycle, so a loop-local
timestamp would reset each pass and the cadence would be meaningless.")

(defconstant +extra-peer-check-interval-seconds+ 45
  "Core EXTRA_PEER_CHECK_INTERVAL — cadence of the chain-sync sweep.")

(defun consider-outbound-evictions (node)
  "Core's CheckForStaleTipAndEvictPeers tick (net_processing.cpp:5460), on the
45s EXTRA_PEER_CHECK_INTERVAL cadence. Driven from here rather than from
run-ibd's block-download loop, which does not run at tip — exactly where
eclipse resistance matters.

Two sweeps, in Core's order: the per-peer chain-sync eviction, then the
whole-set extra-outbound eviction."
  (let ((now (bl.ser:get-unix-time)))
    (when (>= (- now *last-chain-sync-check*) +extra-peer-check-interval-seconds+)
      (setf *last-chain-sync-check* now)
      (let ((chain-state (node-current-chainstate node)))
        (when chain-state
          (dolist (peer (node-peers node))
            (handler-case
                (bl.net:consider-chain-sync-eviction
                 peer chain-state now)
              (error (e)
                ;; Per-peer, so one unhappy peer cannot stop the sweep — but
                ;; LOGGED, not swallowed. A silent error here exempts that peer
                ;; from eviction forever, which is indistinguishable from the
                ;; eclipse this code exists to prevent.
                (log-warn "Chain-sync eviction failed for peer ~A: ~A"
                          (bl.net:peer-address peer) e))))))
      ;; Core runs EvictExtraOutboundPeers from this same tick (:5466), and
      ;; BEFORE the stale-tip check rather than after: the peer we are about to
      ;; decide we need is not one we should have dropped on the way in.
      ;;
      ;; Unlike the chain-sync sweep this one is not per-peer — both halves
      ;; rank the set against itself — so it takes the list once, snapshotted
      ;; under the node lock: disconnect-peer runs inside it and mutates state
      ;; the listener thread touches too.
      (handler-case
          (bl.net:evict-extra-outbound-peers
        (bt:with-recursive-lock-held ((node-lock node)) (copy-list (node-peers node)))
        now
        ;; Deliberately the UNRAISED target, even while the extra-outbound slot
        ;; is granted. Core's GetExtraFullOutboundCount does the same
        ;; (net.cpp:2473): the extra peer is supposed to put us one over so the
        ;; rotation drops the stalest one. Passing the raised budget here would
        ;; make the extra connection permanent and silently disable the whole
        ;; rotation.
        (node-max-peers node)
        +target-block-relay-peers+)
        ;; Whole-set, so an error takes the sweep with it — which is exactly
        ;; why it must be visible. This feature's own history is a sweep placed
        ;; where it never ran (see the docstring above); a bare ignore-errors
        ;; would recreate that silently.
        (error (e) (log-warn "Extra-outbound eviction sweep failed: ~A" e)))
      ;; Then the stale-tip half, on its own 10-minute timer. Core's order
      ;; (:5466 then :5468): evict first, so a peer we are about to decide we
      ;; need is not one we just dropped on the way in.
      (handler-case (check-for-stale-tip node now)
        (error (e) (log-warn "Stale-tip check failed: ~A" e))))))

(defun maintain-peers (node)
  "Run periodic peer maintenance: health checks, reconnection, dedicated
block-relay-only slots, an occasional feeler probe, and the chain-sync
eviction sweep."
  (check-peers-health node)
  (connect-added-nodes node)
  (connect-specified-nodes node)
  ;; Core resolves tried-table collisions once per ThreadOpenConnections
  ;; iteration (net.cpp:2768), not only at startup — otherwise, once the
  ;; collision set is full, address-book-good stops recording successes.
  (let ((book (node-address-book node)))
    (when book (bl.net:resolve-tried-collisions book)))
  (consider-outbound-evictions node)
  (replace-disconnected-peers node)
  (maintain-block-relay-peers node)
  (maybe-do-feeler node))
