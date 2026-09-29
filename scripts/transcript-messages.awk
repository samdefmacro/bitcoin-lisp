# Print every compiler message in an SBCL build transcript as one line,
# "FILE<TAB>MESSAGE", attributed to the file being compiled -- the shared
# parser of scripts/check-wrong-arity-calls.sh and check-unused-variables.sh.
#
# A message body is indented under its own "; " prefix and a long one wraps,
# so consecutive continuation lines are joined; the file is the latest
# "; compiling file" line, or the "; file:" line SBCL prints before a
# deferred (end-of-unit) warning.
function flush() {
  if (msg != "") print file "\t" msg
  msg = ""
}
/^;   / { line = substr($0, 5); msg = (msg == "" ? line : msg " " line); next }
{
  flush()
  if ($0 ~ /^; compiling file "/) { f = $0; sub(/^.*compiling file "/, "", f); sub(/".*$/, "", f); file = f }
  else if ($0 ~ /^; file: /) { file = substr($0, 9) }
}
END { flush() }
