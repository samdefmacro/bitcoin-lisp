// App shell: login flow + poll scheduler (gui-plan P0).

import * as rpc from './rpc.js';
import { tick, resetDashboard } from './dashboard.js';

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

function showDashboard() {
  loggedIn = true;
  $('login-view').hidden = true;
  $('dash-view').hidden = false;
  startPolling();
}

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
    showDashboard();
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

if (rpc.hasCredentials()) {
  showDashboard();
} else {
  showLogin();
}
