// The DOM shim the other suites run against has no CSS engine, so `el.hidden
// = true` always "works" there. On a real browser it does not: the UA rule
// `[hidden] { display: none }` loses to ANY author rule that sets `display`,
// whatever its specificity. That gap hid a live bug in which a successful
// login left the login panel on screen and every route rendered all six views
// at once. These tests read the actual stylesheet and markup.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const root = new URL('../../', import.meta.url);
const html = readFileSync(new URL('ui/index.html', root), 'utf8');
// Comments are stripped first: the [hidden] rule's own comment quotes the UA
// declaration verbatim, and a naive scan matches that instead of the rule.
const css = readFileSync(new URL('ui/style.css', root), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '');

// Classes on elements that also carry the `hidden` attribute.
function hidableClasses() {
  const out = new Set();
  for (const tag of html.match(/<[^>]+>/g) ?? []) {
    if (!/\shidden(\s|=|>|\/)/.test(tag)) continue; // aria-hidden must not match
    if (!/\sclass="([^"]*)"/.test(tag)) continue;
    for (const c of RegExp.$1.trim().split(/\s+/)) if (c) out.add(c);
  }
  return out;
}

// Classes whose rule body sets `display`.
function displayClasses() {
  const out = new Set();
  for (const [, sel, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!/display\s*:/.test(body)) continue;
    for (const [, c] of sel.matchAll(/\.([\w-]+)/g)) out.add(c);
  }
  return out;
}

test('the stylesheet overrides display for [hidden] at author level', () => {
  const rule = css.match(/\[hidden\][^{]*\{([^}]*)\}/);
  assert.ok(rule, 'style.css must carry its own [hidden] rule');
  assert.match(rule[1], /display\s*:\s*none\s*!important/,
    '!important is required: [hidden] and .some-class tie on specificity, so a '
    + 'later class rule would otherwise win by source order');
});

test('every class used on a hidable element is covered by that rule', () => {
  const overlap = [...hidableClasses()].filter((c) => displayClasses().has(c));
  // Not an error — the [hidden] rule above is what makes it safe. Asserting
  // the overlap is non-empty keeps the rule above from becoming dead weight
  // that someone deletes as unused.
  assert.ok(overlap.length > 0,
    'expected at least one hidable element to carry a display-setting class');
  assert.ok(overlap.includes('login-wrap') && overlap.includes('grid'),
    `login-wrap and grid are the known cases; got ${overlap.join(', ')}`);
});

test('aria-hidden is not mistaken for hidden', () => {
  assert.ok(!hidableClasses().has('sep'), '.sep only ever carries aria-hidden');
});
