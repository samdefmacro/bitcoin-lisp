"""Extract each RPC method's top-level argument NAMES from Core's RPCHelpMan
declarations, in declaration order.

The names are what transformNamedArguments matches a JSON-RPC named parameter
against (rpc/server.cpp), so they are the table a server needs to accept named
parameters at all. Core's client.cpp — the source #458 generates the type
conversion table from — deliberately lists only arguments that need JSON
conversion, which structurally excludes every STRING argument. Deriving named
parameters from it therefore loses `scantxoutset action`, `setban subnet`, and
so on.
"""
import re, sys, glob

ROOT = 'refs/bitcoin/src'
FILES = (sorted(glob.glob(ROOT + '/rpc/*.cpp'))
         + sorted(glob.glob(ROOT + '/wallet/rpc/*.cpp'))
         + sorted(glob.glob(ROOT + '/zmq/*.cpp')))
ALL = FILES + sorted(glob.glob(ROOT + '/rpc/*.h')) + sorted(glob.glob(ROOT + '/wallet/rpc/*.h'))

def skip_string(s, i):
    i += 1
    while i < len(s):
        if s[i] == '\\': i += 2; continue
        if s[i] == '"': return i + 1
        i += 1
    return i

def skip_trivia(s, i):
    while i < len(s):
        if s[i] in ' \t\r\n': i += 1
        elif s.startswith('//', i):
            j = s.find('\n', i); i = len(s) if j < 0 else j
        elif s.startswith('/*', i):
            j = s.find('*/', i); i = len(s) if j < 0 else j + 2
        else: return i
    return i

OPEN, CLOSE = '({[', ')}]'

def scan_to_top_comma(s, i, stop):
    """Advance to the next comma at nesting depth 0, or to `stop`."""
    depth = 0
    while i < len(s) and i < stop:
        c = s[i]
        if c == '"': i = skip_string(s, i); continue
        if s.startswith('//', i) or s.startswith('/*', i):
            i = skip_trivia(s, i); continue
        if c in OPEN: depth += 1
        elif c in CLOSE:
            if depth == 0: return i
            depth -= 1
        elif c == ',' and depth == 0: return i
        i += 1
    return min(i, stop)

def arg_names_from_vector(s, i):
    """Parse a brace-literal vector of RPCArg entries at s[i]=='{'."""
    names, depth, expect = [], 0, False
    while i < len(s):
        c = s[i]
        if c == '"':
            j = skip_string(s, i)
            if depth == 2 and expect:
                names.append(s[i+1:j-1]); expect = False
            i = j; continue
        if s.startswith('//', i) or s.startswith('/*', i):
            i = skip_trivia(s, i); continue
        if c == '{':
            depth += 1
            if depth == 2: expect = True
            i += 1; continue
        if c == '}':
            depth -= 1
            if depth == 0: return names
            i += 1; continue
        if depth == 1 and (c.isalpha() or c == '_'):
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] == '_'): j += 1
            ident = s[i:j]
            if ident in ARG_CONSTS: names.append(ARG_CONSTS[ident])
            elif ident not in ('RPCArg', 'Type', 'Optional', 'Fallback'):
                UNRESOLVED.add(ident)
            i = j; continue
        i += 1
    return names

# Shared RPCArg constants, both spellings Core uses.
ARG_CONSTS = {}
for path in ALL:
    txt = open(path, encoding='utf-8', errors='replace').read()
    for m in re.finditer(r'RPCArg\s+(\w+)\s*\{\s*"([^"]+)"', txt):
        ARG_CONSTS[m.group(1)] = m.group(2)
    for m in re.finditer(r'\b(\w+)\s*=\s*RPCArg\{\s*\n?\s*"([^"]+)"', txt):
        ARG_CONSTS[m.group(1)] = m.group(2)

UNRESOLVED = set()

# Helper FUNCTIONS that return a vector of RPCArg (CreateTxDoc(), ...): parse
# the vector literal in their body.
HELPERS = {}
for path in ALL:
    txt = open(path, encoding='utf-8', errors='replace').read()
    for m in re.finditer(r'std::vector<RPCArg>\s+(\w+)\s*\(', txt):
        j = txt.find('{', m.end())
        if j < 0: continue
        k = txt.find('return', j)
        if k < 0: continue
        k = skip_trivia(txt, k + len('return'))
        if k < len(txt) and txt[k] == '{':
            HELPERS[m.group(1)] = arg_names_from_vector(txt, k)

results, unresolved_methods = {}, {}
for path in FILES:
    src = open(path, encoding='utf-8', errors='replace').read()
    for m in re.finditer(r'RPCHelpMan\{', src):
        i = m.end()
        i = skip_trivia(src, i)
        if i < len(src) and src[i] == '"':
            j = skip_string(src, i)
            name = src[i+1:j-1]
            if not re.fullmatch(r'[a-z0-9_]+', name): continue
        else:
            # `RPCHelpMan{ method_name, ...}` — a helper that takes the method
            # name as a parameter (bumpfee_helper, echo). File it under the
            # enclosing function's name; the alias pass below maps the real
            # method names onto it.
            back = src.rfind('RPCHelpMan ', 0, m.start())
            if back < 0: continue
            fm = re.match(r'RPCHelpMan\s+(\w+)\s*\(', src[back:])
            if not fm: continue
            name = fm.group(1)
            j = i
            while j < len(src) and (src[j].isalnum() or src[j] == '_'): j += 1
        end_desc = scan_to_top_comma(src, j + 1, len(src))    # end of name..desc
        args_start = skip_trivia(src, end_desc + 1)
        if args_start < len(src) and src[args_start] == '{':
            results[name] = arg_names_from_vector(src, args_start)
        else:
            k = args_start
            while k < len(src) and (src[k].isalnum() or src[k] == '_'): k += 1
            helper = src[args_start:k]
            if helper in HELPERS:
                results[name] = HELPERS[helper]
            else:
                unresolved_methods[name] = helper

# A few methods are declared by a HELPER that takes the method name as an
# argument, so no `RPCHelpMan{"name"` literal exists for them:
#   RPCHelpMan bumpfee() { return bumpfee_helper("bumpfee"); }   (spend.cpp:1166)
#   static RPCHelpMan echojson() { return echo("echojson"); }    (node.cpp:311)
# The helper's own declaration is parsed under its own name; alias the real
# method names onto it.
for path in ALL:
    txt = open(path, encoding='utf-8', errors='replace').read()
    for m in re.finditer(r'RPCHelpMan\s+(\w+)\s*\(\s*\)\s*\{\s*return\s+(\w+)\s*\(\s*"([^"]+)"',
                         txt):
        fn, helper, method = m.group(1), m.group(2), m.group(3)
        if helper in results:
            results[method] = results[helper]

for n in sorted(results):
    print(n, results[n])
print('TOTAL', len(results), file=sys.stderr)
if unresolved_methods:
    print('UNRESOLVED METHODS', unresolved_methods, file=sys.stderr)
if UNRESOLVED:
    print('UNRESOLVED IDENTS', sorted(UNRESOLVED), file=sys.stderr)
