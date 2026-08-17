// GUI P6a QR-encoder tests (docs/gui-plan.md P6a). Run from the repo root:
//
//   scripts/dev.sh ui-test
//
// Zero dependencies: the REAL ui/js/qr.js is compared byte-for-byte against
// machine-generated vectors (tests/ui/qr-vectors.json) from the python
// `qrcode` reference library — byte mode, EC level M, border 0:
//   - all 8 fixed masks for one input (isolates the encoder from mask
//     selection), and
//   - automatic version + mask selection across versions 1-12, including
//     the 8-bit -> 16-bit length-field boundary at version 10 and UTF-8
//     input (vectors were regenerated, never hand-transcribed).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  qrEncode, qrSvgString, qrDataUri, formatBits, versionBits, rsEcBytes,
  pickVersion, buildCodewords,
} from '../../ui/js/qr.js';

const vectors = JSON.parse(
  await readFile(new URL('./qr-vectors.json', import.meta.url), 'utf-8'));

function matrixRows(modules) {
  return modules.map((row) => row.map((m) => (m ? '1' : '0')).join(''));
}

// --- building blocks -----------------------------------------------------

test('format info bits match the published BCH(15,5) values', () => {
  // ISO/IEC 18004 annex C: EC level M (bits 00), masks 0 and 5.
  assert.equal(formatBits(0), 0b101010000010010);
  assert.equal(formatBits(5), 0b100000011001110);
});

test('version info bits match the published BCH(18,6) value for v7', () => {
  // ISO/IEC 18004 annex D example: version 7 -> 000111110010010100.
  assert.equal(versionBits(7), 0b000111110010010100);
});

test('Reed-Solomon parity matches the ISO annex worked example', () => {
  // The 1-M "HELLO WORLD" example: 16 data codewords -> 10 EC codewords.
  const data = [
    0x20, 0x5b, 0x0b, 0x78, 0xd1, 0x72, 0xdc, 0x4d,
    0x43, 0x40, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11,
  ];
  const expected = [196, 35, 39, 119, 235, 215, 231, 226, 93, 23];
  assert.deepEqual([...rsEcBytes(data, 10)], expected);
});

test('version selection: capacity boundaries at EC level M', () => {
  assert.equal(pickVersion(1), 1);
  assert.equal(pickVersion(14), 1);   // v1-M byte capacity
  assert.equal(pickVersion(15), 2);
  assert.equal(pickVersion(180), 9);  // fits the 8-bit length field era
  assert.equal(pickVersion(213), 10); // 16-bit length field from v10
  assert.equal(pickVersion(2331), 40);
  assert.throws(() => pickVersion(2332), /too long/);
});

test('codeword stream: mode/length header, terminator, EC/11 padding', () => {
  // 'A' in v1-M: 0100 00000001 01000001 0000 pad -> 40 14 10 EC 11 ...
  const words = buildCodewords(new TextEncoder().encode('A'), 1);
  assert.equal(words.length, 26); // 16 data + 10 EC interleaved
  assert.deepEqual(words.slice(0, 6), [0x40, 0x14, 0x10, 0xec, 0x11, 0xec]);
});

// --- full-matrix vectors ----------------------------------------------

for (const v of vectors.fixed) {
  test(`fixed mask ${v.mask}: matrix is byte-exact (v${v.version})`, () => {
    const enc = qrEncode(v.text, v.mask);
    assert.equal(enc.version, v.version);
    assert.equal(enc.size, v.version * 4 + 17);
    assert.deepEqual(matrixRows(enc.modules), v.rows);
  });
}

for (const v of vectors.auto) {
  test(`auto mask/version [${v.name}]: matrix is byte-exact (v${v.version}, mask ${v.mask})`, () => {
    const enc = qrEncode(v.text);
    assert.equal(enc.version, v.version);
    assert.equal(enc.mask, v.mask);
    assert.deepEqual(matrixRows(enc.modules), v.rows);
  });
}

// --- rendering ------------------------------------------------------------

test('SVG output: self-contained, quiet zone, one module per path cell', () => {
  const svg = qrSvgString('bitcoin:tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');
  const { size, modules } = qrEncode('bitcoin:tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');
  assert.match(svg, new RegExp(`viewBox="0 0 ${size + 8} ${size + 8}"`));
  assert.ok(!svg.includes('http://') || svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"'),
    'no external references beyond the xmlns');
  const dark = modules.flat().filter(Boolean).length;
  assert.equal((svg.match(/h1v1h-1z/g) || []).length, dark);
});

test('data URI is an encoded same-document SVG', () => {
  const uri = qrDataUri('x');
  assert.ok(uri.startsWith('data:image/svg+xml,%3Csvg'));
  assert.equal(decodeURIComponent(uri.slice('data:image/svg+xml,'.length)),
    qrSvgString('x'));
});
