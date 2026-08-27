(in-package #:bitcoin-lisp.rpc)

;;; Web UI static-asset serving (docs/gui-plan.md P0).
;;;
;;; Serves the repo's ui/ directory (a no-build-step, self-contained SPA
;;; that talks to the JSON-RPC endpoint) under /ui/ on the same Hunchentoot
;;; acceptor as JSON-RPC and /rest/. Security posture per the plan:
;;;   - enabled by config flag; when off the dispatcher is not registered
;;;     at all (and ui-handle itself 404s, belt-and-braces),
;;;   - every path is canonicalized through a segment whitelist — no "..",
;;;     no absolute escapes, no dotfiles, no wildcard pathname chars,
;;;   - no write capability: GET/HEAD of files under one directory only.

(defvar *ui-enabled* nil
  "When true, /ui/ serves the web UI static assets (start-node -webui).")

(defvar *ui-directory* nil
  "Directory the /ui/ assets are served from (start-node -webuipath).
NIL means the repo default captured at compile time (*ui-default-directory*).")

(defvar *ui-dispatcher* nil
  "The /ui/ dispatcher function (for cleanup on stop).")

(macrolet ((%repo-ui-directory ()
             ;; Compile-time capture: this file lives at <repo>/src/rpc/, so
             ;; the checked-in UI assets are at <repo>/ui/. A saved image
             ;; keeps the build checkout's path (the production layout);
             ;; -webuipath overrides it when the assets live elsewhere.
             (let ((here (or *compile-file-truename* *load-truename*)))
               (and here
                    (namestring
                     (merge-pathnames
                      "ui/"
                      (uiop:pathname-parent-directory-pathname
                       (uiop:pathname-parent-directory-pathname
                        (uiop:pathname-directory-pathname here)))))))))
  (defparameter *ui-default-directory* (%repo-ui-directory)
    "Default UI asset directory: the repo's ui/ next to src/, resolved from
this file's location at compile time."))

(defun ui-directory ()
  "The directory /ui/ assets are served from: -webuipath when configured,
else the compile-time repo default."
  (or *ui-directory*
      (and *ui-default-directory* (pathname *ui-default-directory*))))

(defparameter +ui-content-types+
  '(("html" . "text/html; charset=utf-8")
    ("js"   . "text/javascript; charset=utf-8")
    ("mjs"  . "text/javascript; charset=utf-8")
    ("css"  . "text/css; charset=utf-8")
    ("svg"  . "image/svg+xml")
    ("json" . "application/json")
    ("png"  . "image/png")
    ("ico"  . "image/x-icon")
    ("txt"  . "text/plain; charset=utf-8")
    ("woff2" . "font/woff2"))
  "Content-Type by file extension for /ui/ assets.")

(defun %ui-safe-segment-p (segment)
  "T when SEGMENT is a safe relative path component: non-empty, does not
start with a dot (rejects \".\", \"..\" and dotfiles), and contains only
alphanumerics, dash, underscore, and interior dots. Everything else —
separators, wildcards, drive colons, NULs, backslashes — is rejected, so a
path built from safe segments can only name a file under the UI directory.
Hunchentoot URL-decodes script-name before we see it, so %2e%2e arrives as
\"..\" and is caught here too."
  (and (plusp (length segment))
       (not (char= (char segment 0) #\.))
       (every (lambda (c)
                (or (char<= #\a c #\z) (char<= #\A c #\Z) (char<= #\0 c #\9)
                    (member c '(#\- #\_ #\.))))
              segment)))

(defun %ui-resolve (rel-path)
  "Map REL-PATH (the URL path after \"/ui/\") to a file pathname under the
UI directory, or NIL when any component is unsafe. \"\" maps to index.html.
Components are assembled with MAKE-PATHNAME so they are literal — never
parsed for . / .. / wildcards."
  (let* ((path (if (zerop (length rel-path)) "index.html" rel-path))
         (segments (uiop:split-string path :separator "/"))
         (dir (ui-directory)))
    (when (and dir (every #'%ui-safe-segment-p segments))
      (let* ((dirs (butlast segments))
             (file (car (last segments)))
             (dot (position #\. file :from-end t))
             (name (if dot (subseq file 0 dot) file))
             (type (and dot (subseq file (1+ dot)))))
        (merge-pathnames
         (make-pathname :directory (and dirs (cons :relative dirs))
                        :name name :type type)
         dir)))))

(defun %ui-error (status message)
  "Plain-text error response for the /ui/ handler."
  (setf (hunchentoot:return-code*) status
        (hunchentoot:content-type*) "text/plain")
  (format nil "~A~%" message))

(defun ui-handle (script-name)
  "Serve the /ui/ static asset named by SCRIPT-NAME (the URL-decoded request
path). Sets status/content-type on the current reply and returns the body.
404 whenever the UI is disabled, the path fails canonicalization, or the
file does not exist."
  (cond
    ((not *ui-enabled*)
     (%ui-error 404 "Web UI is disabled"))
    ;; Bare /ui: redirect so the page's relative asset URLs resolve under /ui/.
    ((string= script-name "/ui")
     (setf (hunchentoot:return-code*) hunchentoot:+http-moved-permanently+
           (hunchentoot:header-out :location) "/ui/")
     "")
    ((not (alexandria:starts-with-subseq "/ui/" script-name))
     (%ui-error 404 "Not a /ui/ path"))
    (t
     (let* ((file (%ui-resolve (subseq script-name 4)))
            ;; TRUENAME of a directory has no :name — treat it as absent.
            (truename (and file (probe-file file))))
       (if (or (null truename) (null (pathname-name truename)))
           (%ui-error 404 "Not found")
           (let ((ext (string-downcase (or (pathname-type file) ""))))
             (setf (hunchentoot:content-type*)
                   (or (cdr (assoc ext +ui-content-types+ :test #'string=))
                       "application/octet-stream")
                   ;; Assets are tiny and change with deploys; skip caching.
                   (hunchentoot:header-out :cache-control) "no-cache")
             (alexandria:read-file-into-byte-vector truename)))))))

(defun ui-dispatch-handler ()
  "Hunchentoot handler for /ui and /ui/* — GET/HEAD only."
  (if (member (hunchentoot:request-method*) '(:get :head))
      (handler-case (ui-handle (hunchentoot:script-name*))
        (error (e)
          (bl::node-log :error "UI handler error: ~A" e)
          (%ui-error 500 "Internal error")))
      (progn
        (setf (hunchentoot:return-code*) hunchentoot:+http-method-not-allowed+)
        "")))

(defun make-ui-dispatcher ()
  "Dispatch-table entry matching exactly /ui or /ui/* (a bare prefix
dispatcher on \"/ui\" would also swallow e.g. /uistats)."
  (lambda (request)
    (let ((script-name (hunchentoot:script-name request)))
      (when (or (string= script-name "/ui")
                (alexandria:starts-with-subseq "/ui/" script-name))
        'ui-dispatch-handler))))

(defun open-browser-to-ui (port)
  "Open the local web UI (http://localhost:PORT/ui/) in the default browser
— start-node's -webuiopen flag for local-daemon runs (gui-plan §4). Failures
are logged and never signal: a headless box just keeps starting."
  (let ((url (format nil "http://localhost:~D/ui/" port)))
    (handler-case
        (let ((command (cond ((uiop:os-macosx-p) (list "open" url))
                             ((uiop:os-unix-p) (list "xdg-open" url))
                             (t nil))))
          (cond
            (command
             (uiop:launch-program command)
             (bl::node-log :info "Opened browser at ~A" url))
            (t
             (bl::node-log
              :warn "No browser opener for this platform; web UI is at ~A" url))))
      (error (e)
        (bl::node-log :warn "Could not open browser at ~A: ~A" url e)))))
