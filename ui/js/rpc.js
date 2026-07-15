// Batched JSON-RPC over fetch (gui-plan P0).
//
// Credentials live in sessionStorage only (per-tab, gone on close) and ride
// as an explicit Authorization header on every request — deliberately NOT
// browser-native Basic auth, so no ambient credential exists for a hostile
// page to ride (the server also rejects cross-Origin POSTs before auth).

const AUTH_KEY = 'bitcoin-lisp.rpc-auth';
const ENDPOINT = '/';

let nextId = 1;

export class RpcError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'RpcError';
    this.code = code;
  }
}

// Auth-level failure (HTTP 401/403): the session should return to login.
export class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthError';
  }
}

function b64(s) {
  // UTF-8-safe base64 (btoa alone chokes on non-latin1 credentials).
  return btoa(String.fromCharCode(...new TextEncoder().encode(s)));
}

// Store credentials for this tab. Empty user AND pass = "no credentials"
// mode (open local RPC): an empty marker is stored so the login state is
// remembered, but no Authorization header is sent.
export function setCredentials(user, pass) {
  sessionStorage.setItem(AUTH_KEY, (user || pass) ? b64(`${user}:${pass}`) : '');
}

export function clearCredentials() {
  sessionStorage.removeItem(AUTH_KEY);
}

export function hasCredentials() {
  return sessionStorage.getItem(AUTH_KEY) !== null;
}

async function post(payload) {
  const headers = { 'Content-Type': 'application/json' };
  const auth = sessionStorage.getItem(AUTH_KEY);
  if (auth) headers['Authorization'] = `Basic ${auth}`;

  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  if (res.status === 401) throw new AuthError('credentials rejected by the node');
  if (res.status === 403) throw new AuthError('request rejected (origin mismatch)');
  if (!res.ok) throw new Error(`node returned HTTP ${res.status}`);
  return res.json();
}

// Single call: resolves to the result, throws RpcError on a JSON-RPC error.
export async function call(method, params = []) {
  const body = await post({ jsonrpc: '2.0', id: nextId++, method, params });
  if (body.error) throw new RpcError(body.error.code, body.error.message);
  return body.result;
}

// Batched call. `calls` is [[method, params?], ...]; resolves to an array of
// { result, error } in the same order (matched by id, never by position).
// Transport/auth failures throw; per-method errors are returned in place so
// one failing card never blanks the whole dashboard.
export async function batch(calls) {
  if (calls.length === 0) return [];
  const requests = calls.map(([method, params = []]) =>
    ({ jsonrpc: '2.0', id: nextId++, method, params }));
  const responses = await post(requests);
  if (!Array.isArray(responses)) throw new Error('malformed batch response');
  const byId = new Map(responses.map((r) => [r.id, r]));
  return requests.map((req) => {
    const r = byId.get(req.id);
    if (!r) return { result: null, error: { code: -1, message: 'missing response' } };
    return { result: r.result ?? null, error: r.error ?? null };
  });
}
