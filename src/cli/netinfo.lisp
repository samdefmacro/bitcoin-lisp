(in-package #:bitcoin-lisp.cli)

;;;; -netinfo (Core bitcoin-cli.cpp NetinfoRequestHandler, :381-749)
;;;
;;; A peers dashboard built from getpeerinfo and getnetworkinfo. Core calls it
;;; a human-readable interface that changes regularly; what its functional
;;; test pins is the header line and where the local services go
;;; (interface_bitcoin_cli.py:92-104), and the layout below follows Core's
;;; format strings column for column so the two can be read side by side.

(defconstant +netinfo-max-level+ 4)

(defclass netinfo-handler ()
  ((level :initform 0 :accessor netinfo-level)
   (outonly :initform nil :accessor netinfo-outonly)))

(defstruct (netinfo-peer (:conc-name np-))
  addr sub-version conn-type network age services transport
  min-ping ping addr-processed addr-rate-limited last-blck last-recv last-send
  last-trxn id mapped-as version addr-relay hb-from hb-to outbound tx-relay)

(defmethod prepare-request ((h netinfo-handler) method args)
  (declare (ignore method))
  (when args
    (let* ((s (first args))
           (n (and (plusp (length s)) (every #'digit-char-p s) (<= (length s) 3)
                   (let ((v (parse-integer s))) (and (<= v 255) v)))))
      (unless n
        (cli-error "invalid -netinfo level argument: ~A~%For more information, run: bitcoin-cli -netinfo help" s))
      (setf (netinfo-level h) (min n +netinfo-max-level+))
      (when (rest args)
        (let ((o (second args)))
          (cond ((and (plusp n) (member o '("o" "outonly") :test #'string=))
                 (setf (netinfo-outonly h) t))
                ((plusp n)
                 (cli-error "invalid -netinfo outonly argument: ~A~%For more information, run: bitcoin-cli -netinfo help" o))
                (t
                 (cli-error "invalid -netinfo outonly argument: ~A~%The outonly argument is only valid for a level greater than 0 (the first argument). For more information, run: bitcoin-cli -netinfo help" o)))))))
  (uv-arr (json-rpc-request "getpeerinfo" :null 0)
          (json-rpc-request "getnetworkinfo" :null 1)))

(defun %chain-suffix ()
  "Core ChainToString: the chain after the client version, mainnet empty."
  (ecase *cli-network*
    (:mainnet "") (:testnet3 " testnet") (:testnet4 " testnet4")
    (:signet " signet") (:regtest " regtest")))

(defun %ping-string (seconds)
  "Core PingTimeToString: milliseconds, `-' past 999999, empty when unknown."
  (if (< seconds 0)
      ""
      (let ((ms (round (* 1000 seconds))))
        (if (> ms 999999) "-" (princ-to-string ms)))))

(defun %conn-type-for-netinfo (conn-type)
  (cond ((string= conn-type "outbound-full-relay") "full")
        ((string= conn-type "block-relay-only") "block")
        ((member conn-type '("manual" "feeler") :test #'string=) conn-type)
        ((string= conn-type "addr-fetch") "addr")
        ((string= conn-type "private-broadcast") "priv")
        (t "")))

(defun format-services (services)
  "Core FormatServices: one letter per service name -- `l' for
NETWORK_LIMITED, `2' for P2P_V2, else the name's first letter in lower case."
  (with-output-to-string (out)
    (dolist (s (if (uv-null-p services) nil (uv-values services)))
      (write-char (cond ((string= s "NETWORK_LIMITED") #\l)
                        ((string= s "P2P_V2") #\2)
                        (t (char-downcase (char s 0))))
                  out))))

(defun services-list (services)
  "Core ServicesList: the names, comma separated, lower case, `_' as space."
  (substitute #\Space #\_
              (string-downcase (format nil "~{~A~^, ~}"
                                       (if (uv-null-p services) nil (uv-values services))))))

(defun %opt-int (v default) (if (uv-null-p v) default (uv-get-int v)))

(defun %netinfo-peer (peer network-id now)
  (let ((conn-time (uv-get-int (uv-get peer "conntime"))))
    (make-netinfo-peer
     :addr (uv-get-str (uv-get peer "addr"))
     :sub-version (uv-get-str (uv-get peer "subver"))
     :conn-type (uv-get-str (uv-get peer "connection_type"))
     :network (aref *network-short-names* network-id)
     :age (if (zerop conn-time) "" (princ-to-string (floor (- now conn-time) 60)))
     :services (format-services (uv-get peer "servicesnames"))
     :transport (let ((v (uv-get peer "transport_protocol_type")))
                  (if (uv-null-p v) "v1" (uv-get-str v)))
     :min-ping (let ((v (uv-get peer "minping"))) (if (uv-null-p v) -1 (uv-get-real v)))
     :ping (let ((v (uv-get peer "pingtime"))) (if (uv-null-p v) -1 (uv-get-real v)))
     :addr-processed (%opt-int (uv-get peer "addr_processed") 0)
     :addr-rate-limited (%opt-int (uv-get peer "addr_rate_limited") 0)
     :last-blck (uv-get-int (uv-get peer "last_block"))
     :last-recv (uv-get-int (uv-get peer "lastrecv"))
     :last-send (uv-get-int (uv-get peer "lastsend"))
     :last-trxn (uv-get-int (uv-get peer "last_transaction"))
     :id (uv-get-int (uv-get peer "id"))
     :mapped-as (%opt-int (uv-get peer "mapped_as") 0)
     :version (uv-get-int (uv-get peer "version"))
     :addr-relay (let ((v (uv-get peer "addr_relay_enabled"))) (and (not (uv-null-p v)) (uv-get-bool v)))
     :hb-from (uv-get-bool (uv-get peer "bip152_hb_from"))
     :hb-to (uv-get-bool (uv-get peer "bip152_hb_to"))
     :outbound (not (uv-get-bool (uv-get peer "inbound")))
     :tx-relay (let ((v (uv-get peer "relaytxes"))) (or (uv-null-p v) (uv-get-bool v))))))

(defun %netinfo-peer-table (h peers now out)
  "The peers listing of levels 1-4 (bitcoin-cli.cpp:564-608)."
  (let* ((level (netinfo-level h))
         (addr-p (member level '(2 4)))
         (version-p (member level '(3 4)))
         (w-addr (reduce #'max peers :key (lambda (p) (1+ (length (np-addr p)))) :initial-value 0))
         (w-addrp (reduce #'max peers :key (lambda (p) (length (princ-to-string (np-addr-processed p))))
                          :initial-value 5))
         (w-addrl (reduce #'max peers :key (lambda (p) (length (princ-to-string (np-addr-rate-limited p))))
                          :initial-value 6))
         (w-age (reduce #'max peers :key (lambda (p) (length (np-age p))) :initial-value 5))
         (w-id (reduce #'max peers :key (lambda (p) (length (princ-to-string (np-id p)))) :initial-value 2))
         (w-serv (reduce #'max peers :key (lambda (p) (length (np-services p))) :initial-value 6))
         (asmap (some (lambda (p) (/= 0 (np-mapped-as p))) peers)))
    (flet ((ago (stamp) (if (zerop stamp) "" (princ-to-string (- now stamp))))
           (ago-min (stamp) (princ-to-string (floor (- now stamp) 60))))
      (format out "<->   type   net ~v@A  v  mping   ping send recv  txn  blk  hb ~v@A~v@A~v@A "
              w-serv "serv" w-addrp "addrp" w-addrl "addrl" w-age "age")
      (when asmap (write-string " asmap " out))
      (format out "~v@A ~vA~A~%" w-id "id" (if addr-p w-addr 0) (if addr-p "address" "")
              (if version-p "version" ""))
      (dolist (p (stable-sort (copy-list peers)
                              (lambda (a b)
                                (or (and (not (np-outbound a)) (np-outbound b))
                                    (and (eq (np-outbound a) (np-outbound b))
                                         (< (np-min-ping a) (np-min-ping b)))))))
        (let ((version (format nil "~D~A" (np-version p) (np-sub-version p)))
              (tp (np-transport p)))
          (format out "~3@A ~6@A ~5@A ~v@A ~2@A~7@A~7@A~5@A~5@A~5@A~5@A  ~2@A ~v@A~v@A~v@A~v@A ~v@A ~vA~A~%"
                  (if (np-outbound p) "out" "in")
                  (%conn-type-for-netinfo (np-conn-type p))
                  (np-network p)
                  w-serv (np-services p)
                  (if (and (= (length tp) 2) (char= (char tp 0) #\v)) (char tp 1) #\Space)
                  (%ping-string (np-min-ping p))
                  (%ping-string (np-ping p))
                  (ago (np-last-send p))
                  (ago (np-last-recv p))
                  (cond ((/= 0 (np-last-trxn p)) (ago-min (np-last-trxn p)))
                        ((np-tx-relay p) "")
                        (t "*"))
                  (if (zerop (np-last-blck p)) "" (ago-min (np-last-blck p)))
                  (format nil "~A~A" (if (np-hb-to p) "." " ") (if (np-hb-from p) "*" " "))
                  w-addrp (cond ((/= 0 (np-addr-processed p)) (princ-to-string (np-addr-processed p)))
                                ((np-addr-relay p) "")
                                (t "."))
                  w-addrl (if (zerop (np-addr-rate-limited p)) "" (princ-to-string (np-addr-rate-limited p)))
                  w-age (np-age p)
                  (if asmap 7 0) (if (and asmap (/= 0 (np-mapped-as p))) (princ-to-string (np-mapped-as p)) "")
                  w-id (np-id p)
                  (if addr-p w-addr 0) (if addr-p (np-addr p) "")
                  (if (and version-p (string/= version "0")) version ""))))
      (format out "                ~vA         ms     ms  sec  sec  min  min                ~v@A~%~%"
              w-serv "" w-age "min"))))

(defun %netinfo-counts-table (networkinfo counts block-relay manual out)
  "The peer counts by network and direction (bitcoin-cli.cpp:611-645)."
  (write-string "     " out)
  (let ((reachable nil))
    (dolist (network (uv-values (uv-get networkinfo "networks")))
      (when (uv-get-bool (uv-get network "reachable"))
        (let* ((name (uv-get-str (uv-get network "name")))
               (id (network-id name)))
          (when id
            (format out "~8@A" name)
            (push id reachable)))))
    (dolist (id '(0 6))                 ; UNREACHABLE_NETWORK_IDS: npr, internal
      (unless (zerop (aref counts 2 id))
        (format out "~8@A" (aref *network-short-names* id))
        (push id reachable)))
    (setf reachable (nreverse reachable))
    (write-string "   total   block" out)
    (when (plusp manual) (write-string "  manual" out))
    (loop for row in '("in" "out" "total")
          for i from 0
          do (format out "~%~5A" row)
             (dolist (n reachable) (format out "~8D" (aref counts i n)))
             (format out "   ~5D" (aref counts i (length *networks*)))
             (when (= i 1)
               (format out "   ~5D" block-relay)
               (when (plusp manual) (format out "   ~5D" manual))))))

(defun %netinfo-local-addresses (networkinfo out)
  (write-string (format nil "~%~%Local addresses") out)
  (let ((addrs (uv-values (uv-get networkinfo "localaddresses"))))
    (if (null addrs)
        (format out ": n/a~%")
        (let ((width (reduce #'max addrs :key (lambda (a) (1+ (length (uv-get-str (uv-get a "address"))))))))
          (dolist (a addrs)
            (format out "~%~vA    port ~6D    score ~6D" width (uv-get-str (uv-get a "address"))
                    (uv-get-int (uv-get a "port")) (uv-get-int (uv-get a "score"))))))))

(defun %netinfo-server-version-ok-p (networkinfo)
  "Core refuses a server older than v0.21 (bitcoin-cli.cpp:519-521), whose
getpeerinfo lacks the fields read here. This node numbers its own releases
 (0.1.0 is 100), so the gate applies to a server that names itself Core's
 (/Satoshi:...), and this node -- which carries every field the gate protects
 -- is let through by its own subversion."
  (or (>= (uv-get-int (uv-get networkinfo "version")) 209900)
      (let ((sub (uv-val-str (uv-get networkinfo "subversion"))))
        (search "/bitcoin-lisp:" sub))))

(defmethod process-reply ((h netinfo-handler) batch-in)
  (let* ((batch (process-batch-reply batch-in))
         (networkinfo (uv-get (aref batch 1) "result")))
    (cond ((not (uv-null-p (uv-get (aref batch 0) "error"))) (aref batch 0))
          ((not (uv-null-p (uv-get (aref batch 1) "error"))) (aref batch 1))
          (t
           (unless (%netinfo-server-version-ok-p networkinfo)
             (cli-error "-netinfo requires bitcoind server to be running v0.21.0 and up"))
           (json-rpc-reply (%netinfo-text h (uv-get (aref batch 0) "result") networkinfo))))))

(defun %netinfo-text (h peerinfo networkinfo)
  (let ((now (- (get-universal-time) #.(encode-universal-time 0 0 0 1 1 1970 0)))
        (counts (make-array (list 3 (1+ (length *networks*))) :initial-element 0))
        (block-relay 0) (manual 0) (peers nil)
        (details (plusp (netinfo-level h))))
    (dolist (peer (uv-values peerinfo))
      (let ((id (network-id (uv-get-str (uv-get peer "network")))))
        (when id
          (let ((outbound (not (uv-get-bool (uv-get peer "inbound"))))
                (conn-type (uv-get-str (uv-get peer "connection_type"))))
            (dolist (row (list (if outbound 1 0) 2))
              (incf (aref counts row id))
              (incf (aref counts row (length *networks*))))
            (when (string= conn-type "block-relay-only") (incf block-relay))
            (when (string= conn-type "manual") (incf manual))
            (when (and details (or outbound (not (netinfo-outonly h))))
              (push (%netinfo-peer peer id now) peers))))))
    (with-output-to-string (out)
      (format out "~A client v~A~A - server ~D~A~A~%~%"
              bl.cfg:+client-name+ (bl.ser:client-version-string) (%chain-suffix)
              (uv-get-int (uv-get networkinfo "protocolversion"))
              (uv-get-str (uv-get networkinfo "subversion"))
              (if details
                  (format nil " - services ~A" (format-services (uv-get networkinfo "localservicesnames")))
                  ""))
      (when (and details peers)
        (%netinfo-peer-table h (nreverse peers) now out))
      (%netinfo-counts-table networkinfo counts block-relay manual out)
      (unless details
        (format out "~%~%Local services: ~A" (services-list (uv-get networkinfo "localservicesnames"))))
      (%netinfo-local-addresses networkinfo out))))

(defparameter *netinfo-help*
  "-netinfo (level [outonly]) | help

Returns a network peer connections dashboard with information from the remote server.
This human-readable interface will change regularly and is not intended to be a stable API.
Under the hood, -netinfo fetches the data by calling getpeerinfo and getnetworkinfo.
An optional argument from 0 to 4 can be passed for different peers listings; values above 4 up to 255 are parsed as 4.
If that argument is passed, an optional additional \"outonly\" argument may be passed to obtain the listing with outbound peers only.
Pass \"help\" or \"h\" to see this detailed help documentation.
If more than two arguments are passed, only the first two are read and parsed.
Suggestion: use -netinfo with the Linux watch(1) command for a live dashboard; see example below.

Arguments:
1. level (integer 0-4, optional)  Specify the info level of the peers dashboard (default 0):
                                  0 - Peer counts for each reachable network as well as for block relay peers
                                      and manual peers, and the list of local addresses and ports
                                  1 - Like 0 but preceded by a peers listing (without address and version columns)
                                  2 - Like 1 but with an address column
                                  3 - Like 1 but with a version column
                                  4 - Like 1 but with both address and version columns
2. outonly (\"outonly\" or \"o\", optional) Return the peers listing with outbound peers only, i.e. to save screen space
                                        when a node has many inbound peers. Only valid if a level is passed.

help (\"help\" or \"h\", optional) Print this help documentation instead of the dashboard.

Result:

* The peers listing in levels 1-4 displays all of the peers sorted by direction and minimum ping time:

  Column   Description
  ------   -----------
  <->      Direction
           \"in\"  - inbound connections are those initiated by the peer
           \"out\" - outbound connections are those initiated by us
  type     Type of peer connection
           \"full\"   - full relay, the default
           \"block\"  - block relay; like full relay but does not relay transactions or addresses
           \"manual\" - peer we manually added using RPC addnode or the -addnode/-connect config options
           \"feeler\" - short-lived connection for testing addresses
           \"addr\"   - address fetch; short-lived connection for requesting addresses
           \"priv\"   - private broadcast; short-lived connection for broadcasting our transactions
  net      Network the peer connected through (\"ipv4\", \"ipv6\", \"onion\", \"i2p\", \"cjdns\", or \"npr\" (not publicly routable))
  serv     Services offered by the peer
           \"n\" - NETWORK: peer can serve the full block chain
           \"b\" - BLOOM: peer can handle bloom-filtered connections (see BIP 111)
           \"w\" - WITNESS: peer can be asked for blocks and transactions with witness data (SegWit)
           \"c\" - COMPACT_FILTERS: peer can handle basic block filter requests (see BIPs 157 and 158)
           \"l\" - NETWORK_LIMITED: peer limited to serving only the last 288 blocks (~2 days)
           \"2\" - P2P_V2: peer supports version 2 P2P transport protocol, as defined in BIP 324
           \"u\" - UNKNOWN: unrecognized bit flag
  v        Version of transport protocol used for the connection
  mping    Minimum observed ping time, in milliseconds (ms)
  ping     Last observed ping time, in milliseconds (ms)
  send     Time since last message sent to the peer, in seconds
  recv     Time since last message received from the peer, in seconds
  txn      Time since last novel transaction received from the peer and accepted into our mempool, in minutes
           \"*\" - we do not relay transactions to this peer (getpeerinfo \"relaytxes\" is false)
  blk      Time since last novel block passing initial validity checks received from the peer, in minutes
  hb       High-bandwidth BIP152 compact block relay
           \".\" (to)   - we selected the peer as a high-bandwidth peer
           \"*\" (from) - the peer selected us as a high-bandwidth peer
  addrp    Total number of addresses processed, excluding those dropped due to rate limiting
           \".\" - we do not relay addresses to this peer (getpeerinfo \"addr_relay_enabled\" is false)
  addrl    Total number of addresses dropped due to rate limiting
  age      Duration of connection to the peer, in minutes
  asmap    Mapped AS (Autonomous System) number at the end of the BGP route to the peer, used for diversifying
           peer selection (only displayed if the -asmap config option is set)
  id       Peer index, in increasing order of peer connections since node startup
  address  IP address and port of the peer
  version  Peer version and subversion concatenated, e.g. \"70016/Satoshi:21.0.0/\"

* The peer counts table displays the number of peers for each reachable network as well as
  the number of block relay peers and manual peers.

* The local addresses table lists each local address broadcast by the node, the port, and the score.

Examples:

Peer counts table of reachable networks and list of local addresses
> bitcoin-cli -netinfo

The same, preceded by a peers listing without address and version columns
> bitcoin-cli -netinfo 1

Full dashboard
> bitcoin-cli -netinfo 4

Full dashboard, but with outbound peers only
> bitcoin-cli -netinfo 4 outonly

Full live dashboard, adjust --interval or --no-title as needed (Linux)
> watch --interval 1 --no-title bitcoin-cli -netinfo 4

See this help
> bitcoin-cli -netinfo help
"
  "Core NetinfoRequestHandler::m_help_doc (bitcoin-cli.cpp:652-747), with
NETINFO_MAX_LEVEL substituted: what `bitcoin-cli -netinfo help' prints.")
