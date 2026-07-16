// Tiny hash router (gui-plan P2). Permalinks like #/block/<hash>?page=2,
// #/block-height/<n>, and #/tx/<txid> deep-link directly and survive reload;
// hashchange drives view switches.

let handler = null;

// '#/name/arg1/arg2?k=v' -> { name, args, query }. '' and '#' and '#/' all
// mean the dashboard.
function parse(rawHash) {
  const hash = rawHash.startsWith('#') ? rawHash.slice(1) : rawHash;
  const q = hash.indexOf('?');
  const path = q >= 0 ? hash.slice(0, q) : hash;
  const query = new URLSearchParams(q >= 0 ? hash.slice(q + 1) : '');
  const segments = path.split('/').filter(Boolean);
  return { name: segments[0] || 'dashboard', args: segments.slice(1), query };
}

function current() { return parse(location.hash); }

// Go to PATH ('/tx/abc…'); re-dispatches even when already there, so
// re-searching the current page still re-renders it.
export function navigate(path) {
  if (location.hash === `#${path}`) dispatch();
  else location.hash = path;
}

// Rewrite the current permalink without a re-dispatch (replaceState fires no
// hashchange) — used to keep pagination state in the URL.
export function replaceHash(path) {
  history.replaceState(null, '', `#${path}`);
}

export function dispatch() { if (handler) handler(current()); }

export function start(onRoute) {
  handler = onRoute;
  window.addEventListener('hashchange', dispatch);
  dispatch();
}
