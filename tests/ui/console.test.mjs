// GUI P4 console-page tests (docs/gui-plan.md P4). Run from the repo root:
//
//   scripts/dev.sh ui-test
//
// Zero dependencies: a minimal DOM shim plus a stubbed global fetch drive
// the REAL ui/js modules — console.js parses Qt-style command lines,
// autocompletes from a fixture `help` response, browses history, renders
// results/errors, and every submission is asserted to POST the exact
// JSON-RPC method/params through the real rpc.js helper. (The fiveam suite
// covers the Lisp side: asset serving, shell wiring, and the `help` output
// format the autocomplete parses.)

import test from 'node:test';
import assert from 'node:assert/strict';

// --- minimal DOM shim ---------------------------------------------------

class ClassList {
  constructor(el) { this.el = el; }
  _list() { return this.el.className.split(/\s+/).filter(Boolean); }
  _set(list) { this.el.className = list.join(' '); }
  add(...cs) { this._set([...new Set([...this._list(), ...cs])]); }
  remove(...cs) { this._set(this._list().filter((c) => !cs.includes(c))); }
  contains(c) { return this._list().includes(c); }
  toggle(c, force) {
    const on = force !== undefined ? force : !this.contains(c);
    if (on) this.add(c); else this.remove(c);
    return on;
  }
}

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.childNodes = [];
    this.className = '';
    this.dataset = {};
    this.hidden = false;
    this.value = '';
    this._text = '';
    this._attrs = {};
    this._listeners = {};
    this.classList = new ClassList(this);
  }
  get children() { return this.childNodes.filter((c) => c instanceof Element); }
  get firstChild() { return this.childNodes[0] ?? null; }
  set textContent(t) { this.childNodes = []; this._text = String(t); }
  get textContent() {
    return this._text + this.childNodes
      .map((c) => (c instanceof Element ? c.textContent : String(c))).join('');
  }
  append(...nodes) { this.childNodes.push(...nodes); }
  appendChild(n) { this.childNodes.push(n); return n; }
  replaceChildren(...nodes) { this._text = ''; this.childNodes = [...nodes]; }
  setAttribute(k, v) { this._attrs[k] = String(v); }
  getAttribute(k) { return this._attrs[k] ?? null; }
  removeAttribute(k) { delete this._attrs[k]; }
  addEventListener(type, fn) { (this._listeners[type] ??= []).push(fn); }
  async dispatch(type, event = {}) {
    event.preventDefault ??= () => {};
    for (const fn of this._listeners[type] ?? []) await fn(event);
  }
  // depth-first search helpers for assertions
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
  find(pred) { for (const n of this.walk()) if (pred(n)) return n; return null; }
  findAll(pred) { return [...this.walk()].filter(pred); }
}

globalThis.document = {
  createElement: (tag) => new Element(tag),
  getElementById: () => null,
};

globalThis.sessionStorage = {
  _m: new Map(),
  getItem(k) { return this._m.has(k) ? this._m.get(k) : null; },
  setItem(k, v) { this._m.set(k, String(v)); },
  removeItem(k) { this._m.delete(k); },
};

// --- stubbed JSON-RPC endpoint -------------------------------------------

// `help` mirrors exactly what src/rpc/methods.lisp rpc-help emits with no
// params: sorted registered method names, one per line.
const METHODS = ['getbestblockhash', 'getblock', 'getblockchaininfo',
  'getblockcount', 'getblockhash', 'help', 'setban', 'uptime'];

const fixtures = {
  help: () => METHODS.join('\n'),
  getblockcount: () => 905003,
  getblockchaininfo: () => ({
    chain: 'testnet4', blocks: 905003, initialblockdownload: false,
  }),
  getblockhash: (params) => (typeof params[0] === 'number'
    ? '0'.repeat(40) + 'abcdef0123456789abcdef01'
    : (() => { throw { code: -1, message: 'JSON value is not an integer as expected' }; })()),
  uptime: () => 424242,
};

const rpcLog = []; // every { method, params } POSTed through rpc.js

globalThis.fetch = async (url, opts) => {
  const payload = JSON.parse(opts.body);
  const requests = Array.isArray(payload) ? payload : [payload];
  const responses = requests.map((r) => {
    rpcLog.push({ method: r.method, params: r.params });
    const fn = fixtures[r.method];
    if (!fn) {
      return { jsonrpc: '2.0', id: r.id, result: null,
        error: { code: -32601, message: 'Method not found' } };
    }
    try {
      return { jsonrpc: '2.0', id: r.id, result: fn(r.params ?? []), error: null };
    } catch (e) {
      return { jsonrpc: '2.0', id: r.id, result: null, error: e };
    }
  });
  // Wave-10 semantics: JSON-RPC 2.0 requests are always HTTP 200 with any
  // error in the body — the console must render from the body.
  return {
    status: 200,
    ok: true,
    json: async () => (Array.isArray(payload) ? responses : responses[0]),
  };
};

// --- the real module under test ------------------------------------------

const consoleView = await import('../../ui/js/console.js');

const container = new Element('main');
await consoleView.show(container); // builds the skeleton + fetches `help`

const input = container.find((n) => n.tagName === 'INPUT');
const suggest = container.find((n) => n.tagName === 'UL');
const logEl = container.find((n) => n.classList.contains('console-log'));
const errEl = container.find((n) => n.classList.contains('error-text'));

async function type(text) {
  input.value = text;
  await input.dispatch('input');
}

async function key(k, extra = {}) {
  await input.dispatch('keydown', { key: k, ...extra });
}

async function run(line) {
  await type(line);
  await key('Enter');
}

function entries() {
  return logEl.findAll((n) => n.classList.contains('console-entry'));
}

function lastEntry() {
  const all = entries();
  return all[all.length - 1];
}

// --- command-line parsing (pure) ------------------------------------------

test('parseCommandLine: no args, ints, floats, literals', () => {
  assert.deepEqual(consoleView.parseCommandLine('getblockcount'),
    { method: 'getblockcount', params: [] });
  assert.deepEqual(consoleView.parseCommandLine('  getblockhash   800000  '),
    { method: 'getblockhash', params: [800000] });
  assert.deepEqual(consoleView.parseCommandLine('settxfee 0.0001'),
    { method: 'settxfee', params: [0.0001] });
  assert.deepEqual(consoleView.parseCommandLine('foo -1.5 2e3'),
    { method: 'foo', params: [-1.5, 2000] });
  assert.deepEqual(consoleView.parseCommandLine('foo true false null'),
    { method: 'foo', params: [true, false, null] });
});

test('parseCommandLine: quoted strings, spaces, escapes', () => {
  assert.deepEqual(consoleView.parseCommandLine('foo "hello world"'),
    { method: 'foo', params: ['hello world'] });
  assert.deepEqual(consoleView.parseCommandLine("foo 'single quoted arg'"),
    { method: 'foo', params: ['single quoted arg'] });
  // inside double quotes only \" and \\ escape (Qt's rule)
  assert.deepEqual(consoleView.parseCommandLine('foo "say \\"hi\\" \\\\ok"'),
    { method: 'foo', params: ['say "hi" \\ok'] });
  // other backslashes inside double quotes stay literal
  assert.deepEqual(consoleView.parseCommandLine('foo "a\\nb"'),
    { method: 'foo', params: ['a\\nb'] });
  // quoting forces string-ness: numbers/JSON stay strings when quoted
  assert.deepEqual(consoleView.parseCommandLine('foo "42" \'[1]\''),
    { method: 'foo', params: ['42', '[1]'] });
  // adjacent quoted pieces concatenate into one argument
  assert.deepEqual(consoleView.parseCommandLine('foo "a b"\'c d\''),
    { method: 'foo', params: ['a bc d'] });
});

test('parseCommandLine: JSON arrays and objects, with interior spaces', () => {
  assert.deepEqual(consoleView.parseCommandLine('submitpackage ["aa","bb"]'),
    { method: 'submitpackage', params: [['aa', 'bb']] });
  assert.deepEqual(
    consoleView.parseCommandLine('foo {"a": 1, "b": [2, 3]} 7'),
    { method: 'foo', params: [{ a: 1, b: [2, 3] }, 7] });
  // brackets inside JSON strings don't confuse the tokenizer
  assert.deepEqual(consoleView.parseCommandLine('foo {"a": "] x ["}'),
    { method: 'foo', params: [{ a: '] x [' }] });
  assert.deepEqual(consoleView.parseCommandLine('foo [1, "two words", null]'),
    { method: 'foo', params: [[1, 'two words', null]] });
});

test('parseCommandLine: bare words stay strings (hashes, hex, addresses)', () => {
  const txid = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  assert.deepEqual(consoleView.parseCommandLine(`getrawtransaction ${txid} 1`),
    { method: 'getrawtransaction', params: [txid, 1] });
  // not JSON numbers => strings: leading zeros, hex digits
  assert.deepEqual(consoleView.parseCommandLine('foo 0123 0000000000000c09 deadbeef'),
    { method: 'foo', params: ['0123', '0000000000000c09', 'deadbeef'] });
  assert.deepEqual(consoleView.parseCommandLine('validateaddress tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'),
    { method: 'validateaddress', params: ['tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'] });
});

test('parseCommandLine: blank input and syntax errors', () => {
  assert.equal(consoleView.parseCommandLine(''), null);
  assert.equal(consoleView.parseCommandLine('   '), null);
  assert.throws(() => consoleView.parseCommandLine('foo [1, 2'), /unbalanced/);
  assert.throws(() => consoleView.parseCommandLine('foo {"a": 1'), /unbalanced/);
  assert.throws(() => consoleView.parseCommandLine('foo ]'), /unbalanced/);
  assert.throws(() => consoleView.parseCommandLine('foo "unterminated'), /unterminated/);
  assert.throws(() => consoleView.parseCommandLine('foo {a: 1}'), /not valid JSON/);
  assert.throws(() => consoleView.parseCommandLine('"getblock" x'), /method name/);
  assert.throws(() => consoleView.parseCommandLine('validateaddress(getnewaddress())'),
    /method name/); // Qt-style nesting is intentionally unsupported
});

test('parseJsonParams: empty -> [], array required', () => {
  assert.deepEqual(consoleView.parseJsonParams(''), []);
  assert.deepEqual(consoleView.parseJsonParams('  \n '), []);
  assert.deepEqual(consoleView.parseJsonParams(' [1, "a", {"k": true}] '),
    [1, 'a', { k: true }]);
  assert.throws(() => consoleView.parseJsonParams('{"k": 1}'), /must be a JSON array/);
  assert.throws(() => consoleView.parseJsonParams('zzz'), /not valid JSON/);
});

// --- autocomplete (pure) ---------------------------------------------------

test('parseHelpText handles our format and Core-style help output', () => {
  assert.deepEqual(consoleView.parseHelpText('aaa\nbbb\nccc'), ['aaa', 'bbb', 'ccc']);
  // tolerate section headers + usage suffixes, blank lines, CRLF
  assert.deepEqual(
    consoleView.parseHelpText('== Blockchain ==\r\ngetblock "blockhash" ( verbosity )\r\n\r\ngetblockcount\r\n'),
    ['getblock', 'getblockcount']);
});

test('buildWordList mirrors Qt: methods plus "help <method>", sorted', () => {
  const words = consoleView.buildWordList(['zeta', 'alpha']);
  assert.deepEqual(words, ['alpha', 'help alpha', 'help zeta', 'zeta']);
});

test('filterCompletions: prefix match, exact match excluded, empty input none', () => {
  const words = consoleView.buildWordList(METHODS);
  assert.deepEqual(consoleView.filterCompletions(words, 'getbl'),
    ['getblock', 'getblockchaininfo', 'getblockcount', 'getblockhash']);
  assert.deepEqual(consoleView.filterCompletions(words, 'help getbl'),
    ['help getblock', 'help getblockchaininfo', 'help getblockcount', 'help getblockhash']);
  assert.deepEqual(consoleView.filterCompletions(words, 'getblockcount'), []);
  assert.deepEqual(consoleView.filterCompletions(words, ''), []);
  assert.deepEqual(consoleView.filterCompletions(words, 'zzz'), []);
});

// --- history (pure) ----------------------------------------------------------

test('history: Qt dedupe/cap/browse semantics with pending-line restore', () => {
  const h = consoleView.createHistory(3);
  h.push('a'); h.push('b'); h.push('c');
  assert.equal(h.browse(-1, 'draft'), 'c');
  assert.equal(h.browse(-1, 'c'), 'b');
  assert.equal(h.browse(-1, 'b'), 'a');
  assert.equal(h.browse(-1, 'a'), 'a'); // clamped at the oldest
  assert.equal(h.browse(1, 'a'), 'b');
  assert.equal(h.browse(1, 'b'), 'c');
  assert.equal(h.browse(1, 'c'), 'draft'); // the in-progress line comes back
  // dedupe: re-running 'a' moves it to the newest slot
  h.push('a');
  assert.deepEqual(h.entries(), ['b', 'c', 'a']);
  // cap: pushing a 4th distinct entry drops the oldest
  h.push('d');
  assert.deepEqual(h.entries(), ['c', 'a', 'd']);
});

test('history persists through sessionStorage', () => {
  const store = {
    _m: new Map(),
    getItem(k) { return this._m.has(k) ? this._m.get(k) : null; },
    setItem(k, v) { this._m.set(k, String(v)); },
  };
  const h1 = consoleView.createHistory(50, store, 'k');
  h1.push('getblockcount');
  h1.push('uptime');
  const h2 = consoleView.createHistory(50, store, 'k');
  assert.deepEqual(h2.entries(), ['getblockcount', 'uptime']);
});

// --- DOM: method list loaded from `help` over rpc.js -------------------------

test('show() fetched the method list via the help RPC', () => {
  assert.deepEqual(rpcLog[0], { method: 'help', params: [] });
});

// --- DOM: submissions POST the exact method/params ---------------------------

test('Enter submits: exact method and converted params through rpc.js', async () => {
  rpcLog.length = 0;
  await run('getblockcount');
  assert.deepEqual(rpcLog, [{ method: 'getblockcount', params: [] }]);
  assert.equal(input.value, '', 'input clears after execution');

  rpcLog.length = 0;
  await run('getblockhash 800000');
  assert.deepEqual(rpcLog, [{ method: 'getblockhash', params: [800000] }]);

  rpcLog.length = 0;
  await run('setban "203.0.113.7" add 86400 true');
  assert.deepEqual(rpcLog,
    [{ method: 'setban', params: ['203.0.113.7', 'add', 86400, true] }]);
});

test('scalar result renders with the command echoed', async () => {
  rpcLog.length = 0;
  await run('uptime');
  const entry = lastEntry();
  const cmd = entry.find((n) => n.classList.contains('console-cmd'));
  assert.equal(cmd.textContent, 'uptime');
  const scalar = entry.find((n) => n.classList.contains('console-scalar'));
  assert.equal(scalar.textContent, '424242');
});

test('object result pretty-prints inside an open collapsible', async () => {
  await run('getblockchaininfo');
  const entry = lastEntry();
  const details = entry.find((n) => n.tagName === 'DETAILS');
  assert.ok(details, 'object results render as <details>');
  assert.equal(details.open, true);
  const summary = details.find((n) => n.tagName === 'SUMMARY');
  assert.match(summary.textContent, /object · 3 fields/);
  const pre = details.find((n) => n.tagName === 'PRE');
  assert.equal(pre.textContent,
    JSON.stringify(fixtures.getblockchaininfo(), null, 2));
  assert.match(pre.textContent, /"chain": "testnet4"/);
});

test('RPC errors render distinctly with code + message from the body', async () => {
  await run('nosuchmethod');
  let err = lastEntry().find((n) => n.classList.contains('console-error'));
  assert.equal(err.textContent, 'error -32601: Method not found');
  // a Core-parity typed-param error surfaces the same way
  await run('getblockhash notanumber');
  err = lastEntry().find((n) => n.classList.contains('console-error'));
  assert.equal(err.textContent, 'error -1: JSON value is not an integer as expected');
});

test('parse errors never reach the wire', async () => {
  rpcLog.length = 0;
  const before = entries().length;
  await run('foo [1, 2');
  assert.equal(rpcLog.length, 0);
  assert.equal(entries().length, before, 'no log entry for a parse failure');
  assert.equal(errEl.hidden, false);
  assert.match(errEl.textContent, /unbalanced/);
  await type(''); // clear the bad line for the next tests
});

// --- DOM: history browsing ----------------------------------------------------

test('ArrowUp/ArrowDown browse history, restoring the draft line', async () => {
  // history so far includes the earlier submissions, newest last
  await type('half-typed draft');
  await key('ArrowUp');
  assert.equal(input.value, 'getblockhash notanumber');
  await key('ArrowUp');
  assert.equal(input.value, 'nosuchmethod');
  await key('ArrowDown');
  assert.equal(input.value, 'getblockhash notanumber');
  await key('ArrowDown');
  assert.equal(input.value, 'half-typed draft');
  await type('');
});

test('re-running a command moves it to the newest history slot', async () => {
  await run('uptime');
  await run('getblockcount');
  await run('uptime'); // dedupe: single 'uptime', now newest
  await key('ArrowUp');
  assert.equal(input.value, 'uptime');
  await key('ArrowUp');
  assert.equal(input.value, 'getblockcount');
  await key('ArrowUp');
  assert.notEqual(input.value, 'uptime', 'the older duplicate was removed');
  await type('');
});

// --- DOM: autocomplete ---------------------------------------------------------

test('typing filters method suggestions from the help list', async () => {
  await type('getbl');
  assert.equal(suggest.hidden, false);
  assert.deepEqual(suggest.children.map((li) => li.textContent),
    ['getblock', 'getblockchaininfo', 'getblockcount', 'getblockhash']);
});

test('ArrowDown selects, Enter completes without executing', async () => {
  rpcLog.length = 0;
  await key('ArrowDown'); // select 'getblock'
  await key('ArrowDown'); // select 'getblockchaininfo'
  assert.equal(suggest.children[1].className, 'active');
  await key('Enter');
  assert.equal(input.value, 'getblockchaininfo');
  assert.equal(rpcLog.length, 0, 'completion must not execute');
  assert.equal(suggest.hidden, true);
  await type('');
});

test('Tab accepts the first suggestion when none is selected', async () => {
  await type('upt');
  await key('Tab');
  assert.equal(input.value, 'uptime');
  assert.equal(suggest.hidden, true);
  await type('');
});

test('help-prefixed completions exist like in Qt', async () => {
  await type('help getblockco');
  assert.deepEqual(suggest.children.map((li) => li.textContent),
    ['help getblockcount']);
  await key('Escape');
  assert.equal(suggest.hidden, true, 'Escape closes the suggestion list');
  await type('');
});

test('with suggestions closed, ArrowUp is history (not selection)', async () => {
  await type('zzz-no-match');
  assert.equal(suggest.hidden, true);
  await key('ArrowUp');
  assert.notEqual(input.value, 'zzz-no-match');
  await type('');
});

// --- DOM: JSON-params mode ------------------------------------------------------

test('JSON mode: textarea params POST raw, command line is method-only', async () => {
  const toggle = container.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'JSON params');
  const paramsWrap = container.find((n) => n.classList.contains('console-params'));
  const area = container.find((n) => n.tagName === 'TEXTAREA');
  assert.equal(paramsWrap.hidden, true);

  await toggle.dispatch('click');
  assert.equal(paramsWrap.hidden, false);
  assert.equal(toggle.getAttribute('aria-pressed'), 'true');

  area.value = ' ["e3b0", 2, {"verbose": true}] ';
  rpcLog.length = 0;
  await run('getblock');
  assert.deepEqual(rpcLog,
    [{ method: 'getblock', params: ['e3b0', 2, { verbose: true }] }]);
  // echo shows the effective call
  const cmd = lastEntry().find((n) => n.classList.contains('console-cmd'));
  assert.equal(cmd.textContent, 'getblock ["e3b0",2,{"verbose":true}]');

  // a full command line in JSON mode is rejected with a parse error
  rpcLog.length = 0;
  await run('getblock e3b0');
  assert.equal(rpcLog.length, 0);
  assert.equal(errEl.hidden, false);
  assert.match(errEl.textContent, /method name/);

  // invalid JSON params are rejected before the wire
  await type('getblock');
  area.value = '{"not": "an array"}';
  rpcLog.length = 0;
  await key('Enter');
  assert.equal(rpcLog.length, 0);
  assert.match(errEl.textContent, /JSON array/);

  // Ctrl+Enter submits from the textarea
  area.value = '[]';
  await type('getblockcount');
  rpcLog.length = 0;
  await area.dispatch('keydown', { key: 'Enter', ctrlKey: true });
  assert.deepEqual(rpcLog, [{ method: 'getblockcount', params: [] }]);

  await toggle.dispatch('click'); // back to command-line mode
  assert.equal(paramsWrap.hidden, true);
});

// --- DOM: clear + reset ----------------------------------------------------------

test('clear empties the log; the placeholder returns', async () => {
  const clearBtn = container.find((n) =>
    n.tagName === 'BUTTON' && n.textContent === 'clear');
  await clearBtn.dispatch('click');
  assert.equal(entries().length, 0);
  assert.ok(logEl.find((n) => n.classList.contains('console-empty')));
  // and the log still works after clearing
  await run('uptime');
  assert.equal(entries().length, 1);
});

test('resetConsole drops the view state; show() rebuilds and refetches help', async () => {
  consoleView.resetConsole();
  rpcLog.length = 0;
  const fresh = new Element('main');
  await consoleView.show(fresh);
  assert.deepEqual(rpcLog, [{ method: 'help', params: [] }]);
  assert.ok(fresh.find((n) => n.classList.contains('console-log')));
});
