"""Extract each RPC method's CATEGORY from Core's command tables.

Core pairs every method with a category in a `static const CRPCCommand
commands[]' table (one per rpc/*.cpp, wallet/rpc/wallet.cpp and zmq/zmqrpc.cpp)
plus `vRPCCommands' in rpc/server.cpp, and CRPCTable::help groups a bare `help'
by that category: it sorts the commands by `category + name', prints
`== ' + Capitalize(category) + ` ==' whenever the category changes, and skips
the ones filed under "hidden" (rpc/server.cpp:69-115).

rpc_help.py's test_categories reads exactly those headings back, so the table
has to be Core's, not a guess. The "hidden" rows are the same source
*RPC-HIDDEN-METHODS* comes from, so both are printed here and cannot drift.

Usage (from the repository root, with refs/bitcoin checked out at the pin):
    python3 scripts/gen-rpc-categories.py            # method category, sorted
    python3 scripts/gen-rpc-categories.py --lisp     # the Lisp table
    python3 scripts/gen-rpc-categories.py --hidden   # just the hidden methods
"""
import re, sys, glob

ROOT = 'refs/bitcoin/src'
FILES = (sorted(glob.glob(ROOT + '/rpc/*.cpp'))
         + sorted(glob.glob(ROOT + '/wallet/rpc/*.cpp'))
         + sorted(glob.glob(ROOT + '/zmq/*.cpp')))

# A table row is `{"category", &method},'. The table itself is either
# `static const CRPCCommand commands[]' (the per-file registrations) or
# `static const CRPCCommand vRPCCommands[]' (rpc/server.cpp's own four), and
# both end at a line that starts with `};'.
TABLE = re.compile(r'(?:static\s+)?const\s+CRPCCommand\s+\w+\[\]\s*\{?\s*$')
ROW = re.compile(r'\{\s*"([a-z]+)"\s*,\s*&(\w+)\s*\}')

rows = {}
for path in FILES:
    in_table = False
    for line in open(path, encoding='utf-8', errors='replace'):
        line = line.rstrip()
        if not in_table:
            if TABLE.search(line):
                in_table = True
            continue
        if line.startswith('};') or line.startswith('    };'):
            in_table = False
            continue
        m = ROW.search(line)
        if m:
            category, method = m.group(1), m.group(2)
            # A method registered twice (Core lists fundrawtransaction under
            # "rawtransactions" from the wallet file) keeps the FIRST row, as
            # mapCommands.front() does.
            rows.setdefault(method, category)

if not rows:
    sys.exit('no CRPCCommand rows found -- is refs/bitcoin checked out?')

if '--hidden' in sys.argv:
    for name in sorted(n for n, c in rows.items() if c == 'hidden'):
        print(name)
elif '--lisp' in sys.argv:
    print('(setf *rpc-categories*')
    print("  '(")
    for name in sorted(rows):
        print('    ("%s" . "%s")' % (name, rows[name]))
    print('    ))')
else:
    for name in sorted(rows):
        print(name, rows[name])
print('TOTAL %d methods, categories: %s'
      % (len(rows), ' '.join(sorted(set(rows.values())))), file=sys.stderr)
