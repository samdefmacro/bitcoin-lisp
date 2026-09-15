"""Extract each RPC method's top-level argument NAMES -- and, with --types,
their RPCArg::Type, or with --required, which of them Core REQUIRES --
from Core's RPCHelpMan declarations, in declaration order.

The names are what transformNamedArguments matches a JSON-RPC named parameter
against (rpc/server.cpp), so they are the table a server needs to accept named
parameters at all. Core's client.cpp — the source the conversion table generates the type
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

def arg_entries_from_vector(s, i):
    """Parse a brace-literal vector of RPCArg entries at s[i]=='{'.

    Returns [(name, type, required)], the type being the RPCArg::Type token of
    the entry or None when the entry carries skip_type_check (Core then runs no
    gate on it at all -- getblock's verbosity, which accepts a bool as well as a
    number). A nested inner argument's skip_type_check disarms its OUTER entry
    too; that errs toward NOT checking, which is the safe direction.

    `required' is RPCArg::IsOptional() inverted (rpc/util.cpp:923-930): true
    only for a fallback spelled RPCArg::Optional::NO. It is read from the
    identifiers at the entry's OWN nesting depth, never from the substring of
    the whole entry, so an inner argument's Optional::NO cannot make an
    optional OBJ or ARR argument look required -- the direction that would
    reject calls Core accepts."""
    entries, depth, expect = [], 0, False
    name = None
    type_ = None
    req = None
    start = None
    while i < len(s):
        c = s[i]
        if c == '"':
            j = skip_string(s, i)
            if depth == 2 and expect:
                name = s[i+1:j-1]; expect = False
            i = j; continue
        if s.startswith('//', i) or s.startswith('/*', i):
            i = skip_trivia(s, i); continue
        if c == '{':
            depth += 1
            if depth == 2:
                expect = True; name = None; type_ = None; req = None; start = i
            i += 1; continue
        if c == '}':
            depth -= 1
            if depth == 1 and name is not None:
                if 'skip_type_check' in s[start:i]:
                    type_ = None
                entries.append((name, type_, bool(req)))
                name = None
            if depth == 0: return entries
            i += 1; continue
        if depth == 2 and (c.isalpha() or c == '_'):
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] == '_' or s[j] == ':'): j += 1
            ident = s[i:j]
            m = re.fullmatch(r'RPCArg::Type::(\w+)', ident)
            if m and type_ is None: type_ = m.group(1)
            if req is None and re.fullmatch(r'RPCArg::(Optional::\w+|Default\w*)', ident):
                req = (ident == 'RPCArg::Optional::NO')
            i = j; continue
        if depth == 1 and (c.isalpha() or c == '_'):
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] == '_'): j += 1
            ident = s[i:j]
            if ident in ARG_CONSTS: entries.append(ARG_CONSTS[ident])
            elif ident not in ('RPCArg', 'Type', 'Optional', 'Fallback'):
                UNRESOLVED.add(ident)
            i = j; continue
        i += 1
    return entries


def arg_names_from_vector(s, i):
    return [e[0] for e in arg_entries_from_vector(s, i)]


def const_required(txt, i):
    """The fallback of a shared RPCArg constant whose header ends at TXT[i]."""
    j = skip_trivia(txt, i)
    if j < len(txt) and txt[j] == ',':
        j = skip_trivia(txt, j + 1)
    return txt.startswith('RPCArg::Optional::NO', j)


# Shared RPCArg constants, both spellings Core uses.
ARG_CONSTS = {}
for path in ALL:
    txt = open(path, encoding='utf-8', errors='replace').read()
    for m in re.finditer(r'RPCArg\s+(\w+)\s*\{\s*"([^"]+)"\s*,\s*RPCArg::Type::(\w+)', txt):
        ARG_CONSTS[m.group(1)] = (m.group(2), m.group(3), const_required(txt, m.end()))
    for m in re.finditer(r'RPCArg\s+(\w+)\s*\{\s*"([^"]+)"', txt):
        ARG_CONSTS.setdefault(m.group(1), (m.group(2), None, const_required(txt, m.end())))
    for m in re.finditer(r'\b(\w+)\s*=\s*RPCArg\{\s*\n?\s*"([^"]+)"\s*,\s*RPCArg::Type::(\w+)', txt):
        ARG_CONSTS[m.group(1)] = (m.group(2), m.group(3), const_required(txt, m.end()))
    for m in re.finditer(r'\b(\w+)\s*=\s*RPCArg\{\s*\n?\s*"([^"]+)"', txt):
        ARG_CONSTS.setdefault(m.group(1), (m.group(2), None, const_required(txt, m.end())))

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
            HELPERS[m.group(1)] = arg_entries_from_vector(txt, k)

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
            results[name] = arg_entries_from_vector(src, args_start)
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

WANT_TYPES = '--types' in sys.argv
WANT_REQUIRED = '--required' in sys.argv
for n in sorted(results):
    if WANT_REQUIRED:
        print(n, [r for (a, t, r) in results[n]])
    elif WANT_TYPES:
        print(n, [(a, t) for (a, t, r) in results[n]])
    else:
        print(n, [a for (a, t, r) in results[n]])
print('TOTAL', len(results), file=sys.stderr)
if unresolved_methods:
    print('UNRESOLVED METHODS', unresolved_methods, file=sys.stderr)
if UNRESOLVED:
    print('UNRESOLVED IDENTS', sorted(UNRESOLVED), file=sys.stderr)


# --- --oneline: Core's RPCArg::ToString(oneline=true) per top-level argument ---
#
# The first line of `help <method>' renders a structured argument as its INNER
# arguments (`[scanobjects,...]', `{"key":n,...}') or as the oneline_description
# its declaration overrides that with (rpc/util.cpp:1249-1290), which the bare
# argument NAME the tables above carry cannot express. This pass parses the
# RPCArg literals RECURSIVELY -- the passes above stop at the top level -- and
# prints one oneline rendering per top-level argument, in declaration order.

def _find_matching(s, i):
    """s[i] is an opener; the index just past its matching closer."""
    depth = 0
    while i < len(s):
        c = s[i]
        if c == '"':
            i = skip_string(s, i); continue
        if s.startswith('//', i) or s.startswith('/*', i):
            i = skip_trivia(s, i); continue
        if c in OPEN:
            depth += 1
        elif c in CLOSE:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def _split_fields(s, start, end):
    """The top-level comma-separated field spans of s[start:end]."""
    fields, depth, i, f0 = [], 0, start, start
    while i < end:
        c = s[i]
        if c == '"':
            i = skip_string(s, i); continue
        if s.startswith('//', i) or s.startswith('/*', i):
            i = skip_trivia(s, i); continue
        if c in OPEN:
            depth += 1
        elif c in CLOSE:
            depth -= 1
        elif c == ',' and depth == 0:
            fields.append((f0, i)); f0 = i + 1
        i += 1
    if s[f0:end].strip():
        fields.append((f0, end))
    return fields


_C_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0',
              '"': '"', "'": "'", '\\': '\\'}


def _unescape(text):
    """A C string literal's body as the characters it denotes: the source
    `\\"\\"' is the two-character string `""', sendmany's oneline_description."""
    out, i = '', 0
    while i < len(text):
        if text[i] == '\\' and i + 1 < len(text):
            out += _C_ESCAPES.get(text[i + 1], text[i + 1])
            i += 2
        else:
            out += text[i]
            i += 1
    return out


def _string_literal(s, a, b):
    """The adjacent C string literals in s[a:b], concatenated and unescaped."""
    out, i = '', a
    while i < b:
        if s[i] == '"':
            j = skip_string(s, i)
            out += _unescape(s[i + 1:j - 1])
            i = j
        else:
            i += 1
    return out


_ONELINE_RE = re.compile(r'\.oneline_description\s*=\s*')
_HIDDEN_RE = re.compile(r'\.hidden\s*=\s*true')

# Shared `static const auto NAME = RPCArg{...}' / `static const RPCArg NAME{...}'
# constants, as the text of their brace group, so a reference to one can be
# parsed like an inline literal.
ARG_LITERALS = {}
for _path in ALL:
    _txt = open(_path, encoding='utf-8', errors='replace').read()
    for _m in re.finditer(r'\b(\w+)\s*=\s*RPCArg\s*\{', _txt):
        _b = _txt.index('{', _m.end() - 1)
        ARG_LITERALS.setdefault(_m.group(1), _txt[_b:_find_matching(_txt, _b)])
    for _m in re.finditer(r'\bRPCArg\s+(\w+)\s*\{', _txt):
        _b = _txt.index('{', _m.end() - 1)
        ARG_LITERALS.setdefault(_m.group(1), _txt[_b:_find_matching(_txt, _b)])


class Arg:
    __slots__ = ('name', 'type', 'inner', 'oneline', 'hidden')

    def __init__(self, name, type_, inner, oneline, hidden):
        self.name, self.type, self.inner = name, type_, inner
        self.oneline, self.hidden = oneline, hidden


def _parse_arg(s, a, b, depth=0):
    """The RPCArg in s[a:b]: a brace literal, `RPCArg{...}', or a reference to
    one of the shared constants above. None when it is neither."""
    if depth > 8:
        return None
    i = skip_trivia(s, a)
    if i >= b:
        return None
    if s[i] != '{':
        m = re.match(r'[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*', s[i:b])
        if not m:
            return None
        ident = m.group(0)
        j = skip_trivia(s, i + len(ident))
        if j < b and s[j] == '{':          # RPCArg{...}
            i = j
        elif ident in ARG_LITERALS:        # a shared constant
            lit = ARG_LITERALS[ident]
            return _parse_arg(lit, 0, len(lit), depth + 1)
        else:
            return None
    end = _find_matching(s, i)
    fields = _split_fields(s, i + 1, end - 1)
    if not fields:
        return None
    name = _string_literal(s, *fields[0])
    type_, inner, oneline, hidden = None, [], None, False
    for (fa, fb) in fields[1:]:
        k = skip_trivia(s, fa)
        if k >= fb:
            continue
        if s[k] == '{':
            kend = _find_matching(s, k)
            inner = [x for x in
                     (_parse_arg(s, ia, ib, depth + 1)
                      for (ia, ib) in _split_fields(s, k + 1, kend - 1))
                     if x is not None]
            continue
        m = re.match(r'RPCArg::Type::(\w+)', s[k:fb])
        if m:
            type_ = m.group(1)
            continue
        if s[k:fb].lstrip().startswith('RPCArgOptions'):
            opts = s[k:fb]
            hidden = bool(_HIDDEN_RE.search(opts))
            om = _ONELINE_RE.search(opts)
            if om:
                oneline = _string_literal(opts, om.end(), len(opts))
    return Arg(name, type_, inner, oneline, hidden)


def _first_name(arg):
    return arg.name.split('|', 1)[0]


def _to_string_obj(arg):
    """RPCArg::ToStringObj(oneline=true) (rpc/util.cpp:1209-1245)."""
    res = '"' + _first_name(arg) + '":'
    t = arg.type
    if t == 'STR':
        return res + '"str"'
    if t == 'STR_HEX':
        return res + '"hex"'
    if t == 'NUM':
        return res + 'n'
    if t == 'RANGE':
        return res + 'n or [n,n]'
    if t == 'AMOUNT':
        return res + 'amount'
    if t == 'BOOL':
        return res + 'bool'
    if t == 'ARR':
        return res + '[' + ''.join(_to_string(i) + ',' for i in arg.inner) + '...]'
    return res + _first_name(arg)


def _to_string(arg):
    """RPCArg::ToString(oneline=true) (rpc/util.cpp:1249-1291)."""
    if arg.oneline:
        return arg.oneline
    t = arg.type
    if t in ('STR', 'STR_HEX'):
        return '"' + _first_name(arg) + '"'
    if t in ('NUM', 'RANGE', 'AMOUNT', 'BOOL'):
        return _first_name(arg)
    if t == 'OBJ':
        return '{' + ','.join(_to_string_obj(i) for i in arg.inner) + '}'
    if t in ('OBJ_NAMED_PARAMS', 'OBJ_USER_KEYS'):
        return '{' + ','.join(_to_string_obj(i) for i in arg.inner) + ',...}'
    if t == 'ARR':
        return '[' + ''.join(_to_string(i) + ',' for i in arg.inner) + '...]'
    return _first_name(arg)


def _oneline_vector(s, i):
    """The oneline renderings of the RPCArg vector literal at s[i] == '{',
    stopping at the first hidden argument as RPCHelpMan::ToString does."""
    end = _find_matching(s, i)
    out = []
    for (a, b) in _split_fields(s, i + 1, end - 1):
        arg = _parse_arg(s, a, b)
        if arg is None:
            return None
        if arg.hidden:
            break
        out.append(_to_string(arg))
    return out


if '--oneline' in sys.argv:
    oneline_results, oneline_helpers = {}, {}
    for path in ALL:
        txt = open(path, encoding='utf-8', errors='replace').read()
        for m in re.finditer(r'std::vector<RPCArg>\s+(\w+)\s*\(', txt):
            j = txt.find('{', m.end())
            if j < 0:
                continue
            k = txt.find('return', j)
            if k < 0:
                continue
            k = skip_trivia(txt, k + len('return'))
            if k < len(txt) and txt[k] == '{':
                oneline_helpers[m.group(1)] = _oneline_vector(txt, k)
    for path in FILES:
        src = open(path, encoding='utf-8', errors='replace').read()
        for m in re.finditer(r'RPCHelpMan\{', src):
            i = skip_trivia(src, m.end())
            if i < len(src) and src[i] == '"':
                j = skip_string(src, i)
                name = src[i + 1:j - 1]
                if not re.fullmatch(r'[a-z0-9_]+', name):
                    continue
            else:
                back = src.rfind('RPCHelpMan ', 0, m.start())
                if back < 0:
                    continue
                fm = re.match(r'RPCHelpMan\s+(\w+)\s*\(', src[back:])
                if not fm:
                    continue
                name = fm.group(1)
                j = i
                while j < len(src) and (src[j].isalnum() or src[j] == '_'):
                    j += 1
            end_desc = scan_to_top_comma(src, j + 1, len(src))
            args_start = skip_trivia(src, end_desc + 1)
            if args_start < len(src) and src[args_start] == '{':
                got = _oneline_vector(src, args_start)
            else:
                k = args_start
                while k < len(src) and (src[k].isalnum() or src[k] == '_'):
                    k += 1
                got = oneline_helpers.get(src[args_start:k])
            if got is not None:
                oneline_results[name] = got
    for path in ALL:
        txt = open(path, encoding='utf-8', errors='replace').read()
        for m in re.finditer(r'RPCHelpMan\s+(\w+)\s*\(\s*\)\s*\{\s*return\s+(\w+)\s*\(\s*"([^"]+)"',
                             txt):
            if m.group(2) in oneline_results:
                oneline_results[m.group(3)] = oneline_results[m.group(2)]
    for n in sorted(oneline_results):
        print(n, oneline_results[n])
    print('ONELINE TOTAL', len(oneline_results), file=sys.stderr)
