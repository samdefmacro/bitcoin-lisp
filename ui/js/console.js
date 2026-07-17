// RPC console (gui-plan P4): method autocomplete sourced from the node's
// `help` RPC, Qt-style space-separated command lines OR a raw JSON params
// textarea, ↑/↓ history, pretty-printed collapsible results.
//
// Command-line parsing mirrors Qt's RPCParseCommandLine (rpcconsole.cpp),
// simplified per gui-plan: no parenthesis command nesting, no result
// queries, and instead of Core's per-method RPCConvertValues table each
// argument is converted on its own shape:
//
//   - "double" or 'single' quoted     -> string (spaces allowed; inside
//     double quotes \" and \\ escape, single quotes are fully literal)
//   - true / false / null             -> JSON literal
//   - a JSON number literal           -> number (so 0123, hex strings and
//     64-hex txids stay strings — they are not JSON numbers)
//   - starts with [ or {              -> JSON.parse'd array/object
//     (whitespace inside brackets/braces does not split arguments)
//   - anything else (bare word)       -> string
//
// History follows Qt: dedupe-then-append, capped at 50 (CONSOLE_HISTORY),
// pointer resets to the end on execute, and the in-progress line is
// restored when you arrow back down past the newest entry. It lives in
// sessionStorage (per-tab, like the credentials) so a reload keeps it.
//
// Safety: nothing executes without an explicit Enter/click, and no method
// is special-cased — this is an operator tool. The wallet selector is out
// of scope until P6.

import * as rpc from './rpc.js';

export const CONSOLE_HISTORY = 50; // Qt rpcconsole.cpp CONSOLE_HISTORY
const HISTORY_KEY = 'bitcoin-lisp.console-history';
const MAX_SUGGESTIONS = 10;

// --- command-line parsing (pure, exported for tests) --------------------

const NUMBER_RE = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$/;
const METHOD_RE = /^[a-z0-9_-]+$/i;

// Split LINE into tokens: { text, quoted }. Unquoted whitespace separates
// tokens except inside [ ] / { } (so inline JSON may contain spaces);
// strings inside that JSON may contain brackets. Throws on unterminated
// quotes or unbalanced brackets.
export function tokenize(line) {
  const tokens = [];
  let cur = '';
  let quoted = false;
  let started = false;
  let depth = 0;
  // normal | double | single | jstring (a "..." inside bracketed JSON)
  let mode = 'normal';
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (mode === 'double') {
      if (ch === '\\' && (line[i + 1] === '"' || line[i + 1] === '\\')) {
        cur += line[i + 1];
        i += 1;
      } else if (ch === '"') {
        mode = 'normal';
      } else {
        cur += ch;
      }
    } else if (mode === 'single') {
      if (ch === "'") mode = 'normal';
      else cur += ch;
    } else if (mode === 'jstring') {
      cur += ch;
      if (ch === '\\') {
        cur += line[i + 1] ?? '';
        i += 1;
      } else if (ch === '"') {
        mode = 'normal';
      }
    } else if (ch === '"' && depth > 0) {
      mode = 'jstring';
      cur += ch;
    } else if (ch === '"' || ch === "'") {
      mode = ch === '"' ? 'double' : 'single';
      quoted = true;
      started = true;
    } else if (/\s/.test(ch) && depth === 0) {
      if (started) {
        tokens.push({ text: cur, quoted });
        cur = '';
        quoted = false;
        started = false;
      }
    } else {
      if (ch === '[' || ch === '{') depth += 1;
      else if (ch === ']' || ch === '}') {
        depth -= 1;
        if (depth < 0) throw new Error(`unbalanced ${ch} in command line`);
      }
      cur += ch;
      started = true;
    }
  }
  if (mode === 'double' || mode === 'single') {
    throw new Error('unterminated quoted string');
  }
  if (mode === 'jstring' || depth !== 0) {
    throw new Error('unbalanced brackets in command line');
  }
  if (started) tokens.push({ text: cur, quoted });
  return tokens;
}

// One token -> one JSON-RPC param, per the header's rules.
export function convertArg(token) {
  if (token.quoted) return token.text;
  const t = token.text;
  if (t === 'true') return true;
  if (t === 'false') return false;
  if (t === 'null') return null;
  if (NUMBER_RE.test(t)) return Number(t);
  if (t[0] === '[' || t[0] === '{') {
    try {
      return JSON.parse(t);
    } catch {
      throw new Error(`argument is not valid JSON: ${t}`);
    }
  }
  return t;
}

// 'getblock "00ab…" 2' -> { method, params }, or null for a blank line.
export function parseCommandLine(line) {
  const tokens = tokenize(line);
  if (tokens.length === 0) return null;
  const [head, ...rest] = tokens;
  if (head.quoted || !METHOD_RE.test(head.text)) {
    throw new Error('expected a method name first (command nesting is not supported)');
  }
  return { method: head.text, params: rest.map(convertArg) };
}

// The raw-JSON textarea: empty means no params; otherwise a JSON array.
export function parseJsonParams(text) {
  const trimmed = text.trim();
  if (!trimmed) return [];
  let value;
  try {
    value = JSON.parse(trimmed);
  } catch (e) {
    throw new Error(`params is not valid JSON: ${e.message}`);
  }
  if (!Array.isArray(value)) throw new Error('params must be a JSON array');
  return value;
}

// --- autocomplete (pure, exported for tests) -----------------------------

// Our rpc-help with no params emits one bare method name per line. Parse
// defensively so Core-style help output (== Section == headers, usage
// suffixes) would also reduce to method names.
export function parseHelpText(text) {
  const names = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const word = line.trim().split(/\s/, 1)[0];
    if (word && !word.startsWith('=')) names.add(word);
  }
  return [...names];
}

// Qt's completer wordlist: every method plus "help <method>", sorted.
export function buildWordList(methods) {
  return [...methods, ...methods.map((m) => `help ${m}`)].sort();
}

// Prefix completions for INPUT (the exact-match candidate is excluded —
// there is nothing left to complete).
export function filterCompletions(wordList, input) {
  const q = input.trimStart();
  if (!q) return [];
  return wordList.filter((w) => w.startsWith(q) && w !== q);
}

// --- history (pure factory, exported for tests) --------------------------

// Qt browseHistory/on_lineEdit_returnPressed semantics. STORAGE is a
// sessionStorage-like object or null for memory-only (tests).
export function createHistory(limit = CONSOLE_HISTORY, storage = null, key = HISTORY_KEY) {
  let items = [];
  if (storage) {
    try {
      const saved = JSON.parse(storage.getItem(key));
      if (Array.isArray(saved)) items = saved.filter((s) => typeof s === 'string');
    } catch { /* corrupt or absent — start empty */ }
  }
  let ptr = items.length;
  let pending = null; // the un-submitted line saved when browsing starts
  const save = () => {
    if (storage) storage.setItem(key, JSON.stringify(items));
  };
  return {
    push(cmd) {
      const dup = items.indexOf(cmd);
      if (dup >= 0) items.splice(dup, 1);
      items.push(cmd);
      while (items.length > limit) items.shift();
      ptr = items.length;
      pending = null;
      save();
    },
    // OFFSET -1 = older (ArrowUp), +1 = newer; returns the line to show.
    browse(offset, current) {
      if (ptr === items.length) pending = current;
      ptr = Math.min(Math.max(ptr + offset, 0), items.length);
      return ptr < items.length ? items[ptr] : (pending ?? current);
    },
    entries() { return [...items]; },
  };
}

// --- module state ---------------------------------------------------------

const state = {
  container: null,
  refs: null,
  methods: [],     // from `help`, once fetched
  wordList: [],
  suggestions: [],
  activeSuggestion: -1,
  jsonMode: false,
  executing: false,
  history: null,
};

export function resetConsole() {
  state.container = null;
  state.refs = null;
  state.methods = [];
  state.wordList = [];
  state.suggestions = [];
  state.activeSuggestion = -1;
  state.jsonMode = false;
  state.executing = false;
  state.history = null;
}

// --- DOM helpers (textContent only for dynamic data — no injection) ---

function el(tag, className = '', text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function rpcErrorParts(e) {
  if (e instanceof rpc.RpcError) return { code: e.code, message: e.message };
  if (e instanceof rpc.AuthError) return { message: `Session ended: ${e.message}` };
  return { message: `Could not reach the node: ${e.message}` };
}

// --- skeleton --------------------------------------------------------------

// Build once per login/container; the log persists across view switches.
// Returns the initial method-list fetch's promise (awaited by tests).
export function show(container) {
  if (state.container !== container || !state.refs) {
    state.container = container;
    buildSkeleton(container);
  }
  state.refs.input.focus?.();
  return loadMethods();
}

async function loadMethods() {
  if (state.methods.length > 0) return; // fetched once; retried while empty
  try {
    const text = await rpc.call('help', []);
    state.methods = parseHelpText(text);
    state.wordList = buildWordList(state.methods);
  } catch { /* autocomplete stays off; retried on the next show() */ }
}

function buildSkeleton(container) {
  const refs = {};
  state.history = createHistory(CONSOLE_HISTORY, globalThis.sessionStorage);

  const card = el('section', 'card card-full');
  card.setAttribute('aria-label', 'RPC console');

  const head = el('div', 'console-head');
  head.appendChild(el('h2', 'card-title', 'RPC console'));
  const clear = el('button', 'linklike', 'clear');
  clear.type = 'button';
  clear.addEventListener('click', () => {
    refs.hasEntries = false;
    refs.log.replaceChildren(refs.logEmpty);
  });
  head.appendChild(clear);
  card.appendChild(head);

  refs.log = el('div', 'console-log');
  refs.log.setAttribute('aria-live', 'polite');
  refs.logEmpty = el('p', 'muted console-empty',
    'Results appear here. Every registered RPC method is available — this '
    + 'is an operator tool with no guard rails.');
  refs.log.appendChild(refs.logEmpty);
  card.appendChild(refs.log);

  const form = el('form', 'console-form');
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    await submit();
  });

  // Suggestions drop up from the input (the input sits under the log).
  refs.suggest = el('ul', 'console-suggest');
  refs.suggest.hidden = true;
  refs.suggest.setAttribute('role', 'listbox');
  refs.suggest.setAttribute('aria-label', 'Method suggestions');

  refs.input = el('input', 'console-input');
  refs.input.value = '';
  refs.input.spellcheck = false;
  refs.input.autocomplete = 'off';
  refs.input.placeholder = 'command — e.g. getblock <hash> 1';
  refs.input.setAttribute('aria-label', 'RPC command');
  refs.input.addEventListener('input', () => updateSuggestions());
  refs.input.addEventListener('keydown', onInputKeydown);

  refs.jsonToggle = el('button', 'btn', 'JSON params');
  refs.jsonToggle.type = 'button';
  refs.jsonToggle.setAttribute('aria-pressed', 'false');
  refs.jsonToggle.title = 'Toggle a raw JSON params box (the line above then holds only the method name)';
  refs.jsonToggle.addEventListener('click', toggleJsonMode);

  const run = el('button', 'btn console-run', 'run');
  run.type = 'submit';
  refs.runBtn = run;

  form.append(refs.suggest, refs.input, refs.jsonToggle, run);
  card.appendChild(form);

  refs.paramsWrap = el('div', 'console-params');
  refs.paramsWrap.hidden = true;
  refs.paramsArea = el('textarea', 'console-json-area');
  refs.paramsArea.value = '';
  refs.paramsArea.spellcheck = false;
  refs.paramsArea.placeholder = '["param1", 2, {"key": "value"}] — a JSON array, or empty for none';
  refs.paramsArea.setAttribute('aria-label', 'JSON params');
  refs.paramsArea.addEventListener('keydown', async (ev) => {
    if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
      ev.preventDefault();
      await submit();
    }
  });
  refs.paramsWrap.appendChild(refs.paramsArea);
  card.appendChild(refs.paramsWrap);

  refs.inputError = el('p', 'error-text');
  refs.inputError.hidden = true;
  card.appendChild(refs.inputError);

  refs.hint = el('p', 'console-hint muted',
    '↑/↓ history · Tab completes · Enter runs');
  card.appendChild(refs.hint);

  state.refs = refs;
  state.suggestions = [];
  state.activeSuggestion = -1;
  state.jsonMode = false;
  container.replaceChildren(card);
}

// --- JSON-mode toggle ------------------------------------------------------

function toggleJsonMode() {
  const { refs } = state;
  state.jsonMode = !state.jsonMode;
  refs.jsonToggle.setAttribute('aria-pressed', String(state.jsonMode));
  refs.jsonToggle.classList.toggle('active', state.jsonMode);
  refs.paramsWrap.hidden = !state.jsonMode;
  refs.input.placeholder = state.jsonMode
    ? 'method name — params come from the JSON box below'
    : 'command — e.g. getblock <hash> 1';
  refs.hint.textContent = state.jsonMode
    ? '↑/↓ history · Tab completes · Enter or Ctrl+Enter runs'
    : '↑/↓ history · Tab completes · Enter runs';
  hideSuggestions();
}

// --- autocomplete UI ---------------------------------------------------

function updateSuggestions() {
  const { refs } = state;
  // In JSON mode only the method word completes; either way, complete the
  // whole line so "help getblock" completions work like Qt's.
  state.suggestions = filterCompletions(state.wordList, refs.input.value)
    .slice(0, MAX_SUGGESTIONS);
  state.activeSuggestion = -1;
  renderSuggestions();
}

function renderSuggestions() {
  const { refs } = state;
  if (state.suggestions.length === 0) {
    refs.suggest.hidden = true;
    refs.suggest.replaceChildren();
    return;
  }
  refs.suggest.hidden = false;
  refs.suggest.replaceChildren(...state.suggestions.map((word, i) => {
    const li = el('li', i === state.activeSuggestion ? 'active' : '', word);
    li.setAttribute('role', 'option');
    if (i === state.activeSuggestion) li.setAttribute('aria-selected', 'true');
    li.addEventListener('click', () => acceptSuggestion(i));
    return li;
  }));
}

function hideSuggestions() {
  state.suggestions = [];
  state.activeSuggestion = -1;
  renderSuggestions();
}

function acceptSuggestion(index) {
  const { refs } = state;
  const word = state.suggestions[index] ?? state.suggestions[0];
  if (!word) return;
  refs.input.value = word;
  hideSuggestions();
  refs.input.focus?.();
}

async function onInputKeydown(ev) {
  const { refs } = state;
  const open = state.suggestions.length > 0;
  switch (ev.key) {
    case 'ArrowDown':
      ev.preventDefault();
      if (open) {
        state.activeSuggestion = Math.min(
          state.activeSuggestion + 1, state.suggestions.length - 1);
        renderSuggestions();
      } else {
        refs.input.value = state.history.browse(1, refs.input.value);
      }
      break;
    case 'ArrowUp':
      ev.preventDefault();
      if (open) {
        state.activeSuggestion = Math.max(state.activeSuggestion - 1, -1);
        renderSuggestions();
      } else {
        refs.input.value = state.history.browse(-1, refs.input.value);
      }
      break;
    case 'Tab':
      if (open) {
        ev.preventDefault();
        acceptSuggestion(Math.max(state.activeSuggestion, 0));
      }
      break;
    case 'Escape':
      if (open) {
        ev.preventDefault();
        hideSuggestions();
      }
      break;
    case 'Enter':
      // Enter with a suggestion actively selected completes it; otherwise
      // it submits (preventDefault keeps the form from double-firing).
      ev.preventDefault();
      if (open && state.activeSuggestion >= 0) {
        acceptSuggestion(state.activeSuggestion);
      } else {
        await submit();
      }
      break;
    default:
      break;
  }
}

// --- the log ---------------------------------------------------------------

function scrollLog() {
  const { log } = state.refs;
  if (typeof log.scrollHeight === 'number') log.scrollTop = log.scrollHeight;
}

// Append the command echo + a pending body; returns the body to fill in.
function appendEntry(echoText) {
  const { refs } = state;
  if (!refs.hasEntries) {
    refs.hasEntries = true;
    refs.log.replaceChildren(); // drop the placeholder on first use
  }
  const entry = el('div', 'console-entry');
  const cmd = el('div', 'console-cmd mono', echoText);
  const body = el('div', 'console-body');
  body.appendChild(el('div', 'muted console-pending', 'executing…'));
  entry.append(cmd, body);
  refs.log.appendChild(entry);
  scrollLog();
  return body;
}

function resultNode(value) {
  if (value !== null && typeof value === 'object') {
    const details = el('details', 'reveal console-json');
    details.open = true;
    const n = Array.isArray(value) ? value.length : Object.keys(value).length;
    const shape = Array.isArray(value)
      ? `array · ${n} item${n === 1 ? '' : 's'}`
      : `object · ${n} field${n === 1 ? '' : 's'}`;
    details.appendChild(el('summary', '', shape));
    details.appendChild(el('pre', '', JSON.stringify(value, null, 2)));
    return details;
  }
  // Strings render raw (no quotes), like Qt; null/booleans/numbers as JSON.
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return el('div', 'console-scalar mono', text ?? 'null');
}

function renderResult(body, value) {
  body.replaceChildren(resultNode(value));
  scrollLog();
}

function renderError(body, { code, message }) {
  const text = code !== undefined ? `error ${code}: ${message}` : message;
  body.replaceChildren(el('div', 'console-error', text));
  scrollLog();
}

// --- submit ------------------------------------------------------------

function showInputError(message) {
  const { inputError } = state.refs;
  inputError.textContent = message;
  inputError.hidden = false;
}

async function submit() {
  const { refs } = state;
  if (state.executing) return; // Qt blocks concurrent execution too
  refs.inputError.hidden = true;
  hideSuggestions();

  const line = (refs.input.value ?? '').trim();
  if (!line) return;

  let method;
  let params;
  let echo;
  try {
    if (state.jsonMode) {
      if (!METHOD_RE.test(line)) {
        throw new Error('in JSON mode the command line holds only the method name');
      }
      method = line;
      params = parseJsonParams(refs.paramsArea.value ?? '');
      echo = params.length ? `${method} ${JSON.stringify(params)}` : method;
    } else {
      const parsed = parseCommandLine(line);
      if (!parsed) return;
      ({ method, params } = parsed);
      echo = line;
    }
  } catch (e) {
    showInputError(e.message);
    return;
  }

  // History records the line as typed (Qt: dedupe, append, cap, reset ptr).
  state.history.push(line);

  const body = appendEntry(echo);
  state.executing = true;
  refs.runBtn.disabled = true;
  try {
    const result = await rpc.call(method, params);
    renderResult(body, result);
  } catch (e) {
    renderError(body, rpcErrorParts(e));
  } finally {
    state.executing = false;
    refs.runBtn.disabled = false;
    refs.input.value = '';
    refs.input.focus?.();
  }
}
