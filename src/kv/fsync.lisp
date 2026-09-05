(in-package #:bitcoin-lisp.kv)

;;;; fsync helpers: the durability half of every temp+rename atomic write.

(defun fsync-file (path)
  "Force the OS to flush PATH's data to durable storage (Core FileCommit,
util/fs_helpers.cpp:102-131). Without this, a temp+rename atomic write can
still leave the destination empty after a crash because the kernel had not
flushed the buffered writes yet.

A failure is logged rather than swallowed, the same way FSYNC-DIRECTORY logs
its own: every branch of Core's FileCommit that fails writes a LogError line
and returns false. It still may not break the write it was protecting -- each
caller has just written a temp file it is about to rename into place -- but a
silent NIL is how a node loses durability with nothing in the log to find it
by. No caller reads the return value, so the log line IS the report."
  #+sbcl
  (handler-case
      (with-open-file (s path :direction :input
                              :element-type '(unsigned-byte 8))
        (sb-posix:fsync (sb-sys:fd-stream-fd s)))
    (error (e)
      (bl.log:log-warn "fsync of file ~A failed: ~A" path e)
      nil))
  #-sbcl nil)

(defun fsync-directory (dir)
  "fsync directory DIR so newly created or renamed names in it are durable
(Core DirectoryCommit, util/fs_helpers.cpp). POSIX does not guarantee a
rename survives a crash until the parent directory is fsynced -- without
this, an atomic temp+fsync+rename can still revert to the old file (or
vanish) after a power loss even though the new data was synced.

DIR must name a DIRECTORY. Handed a file path, open(2) succeeds and fsync(2)
returns 0 on the file's own descriptor, so the call reports success having
synced the wrong inode -- pass FSYNC-PARENT-DIRECTORY a file path instead.

A failure is logged rather than swallowed. It cannot be allowed to break the
write it was protecting, but silence is how a node loses durability without
anyone finding out: every caller here has just renamed a file into place and
believes the name is on disk."
  #+sbcl
  (handler-case
      (let ((fd (sb-posix:open (namestring dir) sb-posix:o-rdonly)))
        (unwind-protect (sb-posix:fsync fd)
          (sb-posix:close fd)))
    (error (e)
      (bl.log:log-warn "fsync of directory ~A failed: ~A" dir e)
      nil))
  #-sbcl nil)

(defun fsync-parent-directory (path)
  "FSYNC-DIRECTORY of the directory containing PATH -- the call every
temp+fsync+rename makes once the rename has returned, since it is the parent
directory that carries the new name.

Take this one whenever what you have is the file's path. FSYNC-DIRECTORY
accepts a file path without complaint and syncs the file, which is the same
thing the call was already doing before its own fsync-file; the rename stays
undurable. That is exactly how the mistake reads at the call site, and how it
survived here: an earlier file-path-taking FSYNC-DIRECTORY was silently
replaced by the directory-taking one (same package, same name) and the four
callers that had been written against it were never converted."
  (let ((dir (directory-namestring path)))
    (fsync-directory (if (string= dir "") "." dir))))
