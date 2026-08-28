(in-package #:bitcoin-lisp.kv)

;;;; fsync helpers: the durability half of every temp+rename atomic write.

(defun fsync-file (path)
  "Force the OS to flush PATH's data to durable storage. Without this,
   a temp+rename atomic write can still leave the destination empty after
   a crash because the kernel hadn't flushed the buffered writes yet."
  #+sbcl
  (handler-case
      (with-open-file (s path :direction :input
                              :element-type '(unsigned-byte 8))
        (sb-posix:fsync (sb-sys:fd-stream-fd s)))
    (error () nil)))

(defun fsync-directory (dir)
  "fsync directory DIR so newly created or renamed names in it are durable
(Core DirectoryCommit, util/fs_helpers.cpp). POSIX does not guarantee a
rename survives a crash until the parent directory is fsynced -- without
this, an atomic temp+fsync+rename can still revert to the old file (or
vanish) after a power loss even though the new data was synced."
  #+sbcl
  (handler-case
      (let ((fd (sb-posix:open (namestring dir) sb-posix:o-rdonly)))
        (unwind-protect (sb-posix:fsync fd)
          (sb-posix:close fd)))
    (error () nil))
  #-sbcl nil)

(defun fsync-parent-directory (path)
  "FSYNC-DIRECTORY of the directory containing PATH, for a file just renamed
into place. This used to be a second FSYNC-DIRECTORY taking a file path; the
later-loaded directory-taking one silently replaced it (same package, same
name), so these calls fsynced the file itself and the parent directory never."
  (let ((dir (directory-namestring path)))
    (fsync-directory (if (string= dir "") "." dir))))
