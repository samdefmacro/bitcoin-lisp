// App shell: login flow, poll scheduler (gui-plan P0), hash routing +
// universal search (gui-plan P2).

import * as rpc from './rpc.js';
import { tick, resetDashboard } from './dashboard.js';
import * as router from './router.js';
import * as explorer from './explorer.js';

const POLL_MS = 3000;

const $ = (id) => document.getElementById(id);

let pollTimer = null;
let pollEpoch = 0; // invalidates in-flight ticks across stop/start
let loggedIn = false;

function setStatus(stateName) {
  $('status-dot').dataset.state = stateName;
}

function showLogin(message = '') {
  loggedIn = false;
  stopPolling();
  rpc.clearCredentials();
  resetDashboard();
  $('dash-view').hidden = true;
  $('login-view').hidden = false;
  const err = $('login-error');
  err.hidden = !message;
  err.textContent = message;
  $('login-user').focus();
}

function showApp() {
  loggedIn = true;
  $('login-view').hidden = true;
  $('dash-view').hidden = false;
  startPolling();
  router.dispatch(); // render whatever view the permalink deep-links to
}

// --- views + routing (gui-plan P2) ---
// The dashboard poll keeps running on every view: it feeds the topbar,
// status dot, and banners, and the dashboard DOM is simply hidden.

const VIEWS = ['dashboard', 'explorer', 'block', 'tx'];

function showView(name, navName = name) {
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== name;
  for (const item of document.querySelectorAll('.nav [data-nav]')) {
    const active = item.dataset.nav === navName;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  }
}

function setSearchError(message) {
  const box = $('search-error');
  box.hidden = !message;
  box.textContent = message || '';
}

function handleRoute(route) {
  if (!loggedIn) return; // login gate; showApp re-dispatches after sign-in
  setSearchError('');
  switch (route.name) {
    case 'dashboard':
      showView('dashboard');
      break;
    case 'block':
    case 'block-height': {
      showView('block', 'explorer');
      const ref = route.name === 'block'
        ? { hash: route.args[0] }
        : { height: route.args[0] };
      explorer.showBlock($('view-block'), ref, route.query.get('page'));
      break;
    }
    case 'tx':
      showView('tx', 'explorer');
      explorer.showTx($('view-tx'), route.args[0]);
      break;
    case 'explorer':
    default:
      showView('explorer');
  }
}

$('search-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const input = $('search-input');
  input.disabled = true;
  try {
    const res = await explorer.search(input.value);
    if (res.ok) {
      input.value = '';
      setSearchError('');
    } else {
      setSearchError(res.message);
    }
  } finally {
    input.disabled = false;
  }
});

// --- poll scheduler: one batched tick, rescheduled after completion; the
// chain stops while the tab is hidden and resumes on visibilitychange. ---

function stopPolling() {
  pollEpoch += 1;
  clearTimeout(pollTimer);
  pollTimer = null;
}

async function poll(epoch) {
  if (epoch !== pollEpoch || document.hidden || !loggedIn) return;
  try {
    await tick();
    setStatus('live');
    $('conn-banner').hidden = true;
  } catch (e) {
    if (e instanceof rpc.AuthError) {
      showLogin(`Session ended: ${e.message}. Sign in again.`);
      return;
    }
    setStatus('down');
    $('conn-banner').hidden = false;
  }
  if (epoch === pollEpoch && !document.hidden && loggedIn) {
    pollTimer = setTimeout(() => poll(epoch), POLL_MS);
  }
}

function startPolling() {
  stopPolling();
  setStatus('idle');
  poll(pollEpoch);
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    stopPolling();
  } else if (loggedIn) {
    startPolling();
  }
});

// --- login ---

$('login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = $('login-btn');
  const err = $('login-error');
  err.hidden = true;

  const cookie = $('login-cookie').value.trim();
  let user = $('login-user').value.trim();
  let pass = $('login-pass').value;
  if (cookie) {
    // .cookie file format is "__cookie__:<secret>"; accept the bare secret too.
    const colon = cookie.indexOf(':');
    if (colon >= 0) {
      user = cookie.slice(0, colon);
      pass = cookie.slice(colon + 1);
    } else {
      user = '__cookie__';
      pass = cookie;
    }
  }

  btn.disabled = true;
  rpc.setCredentials(user, pass);
  try {
    await rpc.call('getblockcount'); // cheap auth probe
    $('login-pass').value = '';
    $('login-cookie').value = '';
    showApp();
  } catch (e) {
    rpc.clearCredentials();
    err.textContent = e instanceof rpc.AuthError
      ? 'The node rejected these credentials.'
      : `Could not reach the node: ${e.message}`;
    err.hidden = false;
  } finally {
    btn.disabled = false;
  }
});

$('logout-btn').addEventListener('click', () => showLogin());

// --- boot: reuse this tab's session if it already has credentials ---

router.start(handleRoute); // no-ops until logged in; showApp re-dispatches
if (rpc.hasCredentials()) {
  showApp();
} else {
  showLogin();
}
