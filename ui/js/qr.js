// Self-contained QR code encoder (gui-plan P6a): byte mode, error
// correction level M, versions 1-40 with automatic version and mask
// selection — everything the receive screen needs, no external deps
// (gui-plan §2: no CDN/external assets ever).
//
// Scope deliberately matches its one caller: BIP21 URIs are ASCII, so byte
// mode alone is optimal (alphanumeric mode cannot encode lowercase bech32).
// Non-ASCII input is UTF-8 encoded, the de-facto standard readers assume.
//
// Byte-exactness: tests/ui/qr.test.mjs compares full matrices against
// machine-generated vectors from the python `qrcode` reference library
// (tests/ui/qr-vectors.json) for all 8 fixed masks and for automatic mask
// selection across versions 1-12, so the tables below and the penalty
// scoring are verified end-to-end, not by eyeball. The two tables were
// machine-extracted from that same reference (never hand-transcribed).

// RS blocks, level M, versions 1-40: runs of [numBlocks, totalCodewords,
// dataCodewords] (ISO/IEC 18004 table 9).
const RS_BLOCKS_M = [
  [[1, 26, 16]],
  [[1, 44, 28]],
  [[1, 70, 44]],
  [[2, 50, 32]],
  [[2, 67, 43]],
  [[4, 43, 27]],
  [[4, 49, 31]],
  [[2, 60, 38], [2, 61, 39]],
  [[3, 58, 36], [2, 59, 37]],
  [[4, 69, 43], [1, 70, 44]],
  [[1, 80, 50], [4, 81, 51]],
  [[6, 58, 36], [2, 59, 37]],
  [[8, 59, 37], [1, 60, 38]],
  [[4, 64, 40], [5, 65, 41]],
  [[5, 65, 41], [5, 66, 42]],
  [[7, 73, 45], [3, 74, 46]],
  [[10, 74, 46], [1, 75, 47]],
  [[9, 69, 43], [4, 70, 44]],
  [[3, 70, 44], [11, 71, 45]],
  [[3, 67, 41], [13, 68, 42]],
  [[17, 68, 42]],
  [[17, 74, 46]],
  [[4, 75, 47], [14, 76, 48]],
  [[6, 73, 45], [14, 74, 46]],
  [[8, 75, 47], [13, 76, 48]],
  [[19, 74, 46], [4, 75, 47]],
  [[22, 73, 45], [3, 74, 46]],
  [[3, 73, 45], [23, 74, 46]],
  [[21, 73, 45], [7, 74, 46]],
  [[19, 75, 47], [10, 76, 48]],
  [[2, 74, 46], [29, 75, 47]],
  [[10, 74, 46], [23, 75, 47]],
  [[14, 74, 46], [21, 75, 47]],
  [[14, 74, 46], [23, 75, 47]],
  [[12, 75, 47], [26, 76, 48]],
  [[6, 75, 47], [34, 76, 48]],
  [[29, 74, 46], [14, 75, 47]],
  [[13, 74, 46], [32, 75, 47]],
  [[40, 75, 47], [7, 76, 48]],
  [[18, 75, 47], [31, 76, 48]],
];

// Alignment pattern center positions, versions 1-40 (table E.1).
const ALIGN_POS = [
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
  [6, 26, 48, 70],
  [6, 26, 50, 74],
  [6, 30, 54, 78],
  [6, 30, 56, 82],
  [6, 30, 58, 86],
  [6, 34, 62, 90],
  [6, 28, 50, 72, 94],
  [6, 26, 50, 74, 98],
  [6, 30, 54, 78, 102],
  [6, 28, 54, 80, 106],
  [6, 32, 58, 84, 110],
  [6, 30, 58, 86, 114],
  [6, 34, 62, 90, 118],
  [6, 26, 50, 74, 98, 122],
  [6, 30, 54, 78, 102, 126],
  [6, 26, 52, 78, 104, 130],
  [6, 30, 56, 82, 108, 134],
  [6, 34, 60, 86, 112, 138],
  [6, 30, 58, 86, 114, 142],
  [6, 34, 62, 90, 118, 146],
  [6, 30, 54, 78, 102, 126, 150],
  [6, 24, 50, 76, 102, 128, 154],
  [6, 28, 54, 80, 106, 132, 158],
  [6, 32, 58, 84, 110, 136, 162],
  [6, 26, 54, 82, 110, 138, 166],
  [6, 30, 58, 86, 114, 142, 170],
];

// --- GF(256) arithmetic (primitive polynomial 0x11d) --------------------

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) GF_EXP[i] = GF_EXP[i - 255];
}

// Reed-Solomon: ECCOUNT parity bytes for DATA (polynomial long division by
// the degree-ECCOUNT generator, built as Π (x - α^i) for i in 0..ecCount-1).
export function rsEcBytes(data, ecCount) {
  const gen = new Uint8Array(ecCount + 1);
  gen[0] = 1;
  for (let i = 0; i < ecCount; i += 1) {
    for (let j = i + 1; j > 0; j -= 1) {
      gen[j] = gen[j] ^ (gen[j - 1] === 0 ? 0
        : GF_EXP[GF_LOG[gen[j - 1]] + i]);
    }
  }
  const rem = new Uint8Array(ecCount);
  for (const byte of data) {
    const factor = byte ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecCount - 1] = 0;
    if (factor !== 0) {
      const lf = GF_LOG[factor];
      for (let j = 0; j < ecCount; j += 1) {
        if (gen[j + 1] !== 0) rem[j] ^= GF_EXP[GF_LOG[gen[j + 1]] + lf];
      }
    }
  }
  return rem;
}

// --- BCH codes for format / version info ---------------------------------

function bchRemainder(value, generator) {
  const genBits = 32 - Math.clz32(generator);
  let v = value;
  while (32 - Math.clz32(v) >= genBits) {
    v ^= generator << ((32 - Math.clz32(v)) - genBits);
  }
  return v;
}

// 15-bit format info for EC level M (bits 00) + MASK, XOR-masked 0x5412.
export function formatBits(mask) {
  const data = (0b00 << 3) | mask; // EC M = 00
  return (((data << 10) | bchRemainder(data << 10, 0x537)) ^ 0x5412) & 0x7fff;
}

// 18-bit version info (versions 7+).
export function versionBits(version) {
  return ((version << 12) | bchRemainder(version << 12, 0x1f25)) & 0x3ffff;
}

// --- data codewords -------------------------------------------------------

function dataCodewordCount(version) {
  return RS_BLOCKS_M[version - 1]
    .reduce((acc, [n, , d]) => acc + n * d, 0);
}

// Smallest version whose level-M data capacity fits BYTES in byte mode.
export function pickVersion(byteLength) {
  for (let v = 1; v <= 40; v += 1) {
    const bits = 4 + (v < 10 ? 8 : 16) + 8 * byteLength;
    if (bits <= dataCodewordCount(v) * 8) return v;
  }
  throw new Error('data too long for a QR code at EC level M');
}

// Byte-mode bit stream -> padded data codewords -> block-interleaved
// data+EC codewords for VERSION.
export function buildCodewords(bytes, version) {
  const dataCount = dataCodewordCount(version);
  const bits = [];
  const putBits = (value, count) => {
    for (let i = count - 1; i >= 0; i -= 1) bits.push((value >> i) & 1);
  };
  putBits(0b0100, 4); // byte mode
  putBits(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) putBits(b, 8);
  // Terminator (up to 4 zero bits), pad to a byte, then 0xEC/0x11 fill.
  putBits(0, Math.min(4, dataCount * 8 - bits.length));
  if (bits.length % 8) putBits(0, 8 - (bits.length % 8));
  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j += 1) b = (b << 1) | bits[i + j];
    codewords.push(b);
  }
  for (let i = 0; codewords.length < dataCount; i += 1) {
    codewords.push(i % 2 === 0 ? 0xec : 0x11);
  }

  // Split into RS blocks; interleave data column-wise, then EC column-wise.
  const dcBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (const [n, total, dc] of RS_BLOCKS_M[version - 1]) {
    for (let k = 0; k < n; k += 1) {
      const block = codewords.slice(offset, offset + dc);
      offset += dc;
      dcBlocks.push(block);
      ecBlocks.push(rsEcBytes(block, total - dc));
    }
  }
  const out = [];
  const maxDc = Math.max(...dcBlocks.map((b) => b.length));
  for (let i = 0; i < maxDc; i += 1) {
    for (const b of dcBlocks) if (i < b.length) out.push(b[i]);
  }
  const maxEc = Math.max(...ecBlocks.map((b) => b.length));
  for (let i = 0; i < maxEc; i += 1) {
    for (const b of ecBlocks) if (i < b.length) out.push(b[i]);
  }
  return out;
}

// --- matrix construction ----------------------------------------------

// The function-pattern skeleton for VERSION: modules[r][c] boolean,
// isFunction[r][c] true where data may not go. Format/version info areas
// are reserved (light) — the real bits are written after mask selection,
// matching the reference's test-mode evaluation.
function baseMatrix(version) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (r, c, dark) => {
    modules[r][c] = dark;
    isFunction[r][c] = true;
  };

  // Finder patterns + separators (out-of-range cells simply don't exist).
  for (const [fr, fc] of [[0, 0], [size - 7, 0], [0, size - 7]]) {
    for (let r = -1; r <= 7; r += 1) {
      for (let c = -1; c <= 7; c += 1) {
        const rr = fr + r;
        const cc = fc + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const dark = (r >= 0 && r <= 6 && (c === 0 || c === 6))
          || (c >= 0 && c <= 6 && (r === 0 || r === 6))
          || (r >= 2 && r <= 4 && c >= 2 && c <= 4);
        set(rr, cc, dark);
      }
    }
  }

  // Alignment patterns (skipped where the center lands on a finder).
  const pos = ALIGN_POS[version - 1];
  for (const row of pos) {
    for (const col of pos) {
      if (isFunction[row][col]) continue;
      for (let r = -2; r <= 2; r += 1) {
        for (let c = -2; c <= 2; c += 1) {
          set(row + r, col + c,
            r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0));
        }
      }
    }
  }

  // Timing patterns.
  for (let i = 8; i < size - 8; i += 1) {
    if (!isFunction[i][6]) set(i, 6, i % 2 === 0);
    if (!isFunction[6][i]) set(6, i, i % 2 === 0);
  }

  // Reserve format info areas + the dark module (written post-mask).
  for (let i = 0; i < 9; i += 1) {
    if (!isFunction[i][8]) set(i, 8, false);
    if (!isFunction[8][i]) set(8, i, false);
  }
  for (let i = 0; i < 8; i += 1) {
    set(size - 1 - i, 8, false);
    set(8, size - 1 - i, false);
  }

  // Reserve version info areas (versions 7+).
  if (version >= 7) {
    for (let i = 0; i < 18; i += 1) {
      set(Math.floor(i / 3), (i % 3) + size - 11, false);
      set((i % 3) + size - 11, Math.floor(i / 3), false);
    }
  }
  return { size, modules, isFunction };
}

const MASK_FN = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r * c) % 3) + ((r + c) % 2)) % 2 === 0,
];

// Zigzag placement: two-column pairs right to left (skipping the timing
// column), serpentine up/down; exhausted data continues as zero bits (they
// still get masked).
function placeData({ size, modules, isFunction }, codewords, mask) {
  const maskFn = MASK_FN[mask];
  let byteIndex = 0;
  let bitIndex = 7;
  let row = size - 1;
  let inc = -1;
  for (let right = size - 1; right > 0; right -= 2) {
    // The column pair left of the timing column shifts by one.
    const col = right <= 6 ? right - 1 : right;
    for (;;) {
      for (const c of [col, col - 1]) {
        if (!isFunction[row][c]) {
          let dark = false;
          if (byteIndex < codewords.length) {
            dark = ((codewords[byteIndex] >> bitIndex) & 1) === 1;
          }
          if (maskFn(row, c)) dark = !dark;
          modules[row][c] = dark;
          bitIndex -= 1;
          if (bitIndex === -1) {
            byteIndex += 1;
            bitIndex = 7;
          }
        }
      }
      row += inc;
      if (row < 0 || row >= size) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
}

function writeFormatAndVersion({ size, modules }, version, mask) {
  const bits = formatBits(mask);
  const bit = (i) => ((bits >> i) & 1) === 1;
  for (let i = 0; i < 15; i += 1) {
    // vertical copy, top-left down / bottom-left up
    if (i < 6) modules[i][8] = bit(i);
    else if (i < 8) modules[i + 1][8] = bit(i);
    else modules[size - 15 + i][8] = bit(i);
    // horizontal copy, top-right leftwards / top-left rightwards
    if (i < 8) modules[8][size - 1 - i] = bit(i);
    else if (i < 9) modules[8][15 - i] = bit(i);
    else modules[8][14 - i] = bit(i);
  }
  modules[size - 8][8] = true; // the dark module

  if (version >= 7) {
    const vbits = versionBits(version);
    for (let i = 0; i < 18; i += 1) {
      const dark = ((vbits >> i) & 1) === 1;
      modules[Math.floor(i / 3)][(i % 3) + size - 11] = dark;
      modules[(i % 3) + size - 11][Math.floor(i / 3)] = dark;
    }
  }
}

// ISO/IEC 18004 mask penalty (N1-N4), same interpretation as the reference
// implementation the vectors come from.
export function penalty(modules) {
  const size = modules.length;
  let score = 0;

  // N1: runs of 5+ same-colored modules in rows and columns.
  for (let axis = 0; axis < 2; axis += 1) {
    for (let i = 0; i < size; i += 1) {
      let run = 0;
      let prev = null;
      for (let j = 0; j < size; j += 1) {
        const m = axis === 0 ? modules[i][j] : modules[j][i];
        if (m === prev) run += 1;
        else {
          if (run >= 5) score += run - 2;
          run = 1;
          prev = m;
        }
      }
      if (run >= 5) score += run - 2;
    }
  }

  // N2: every 2x2 block of one color.
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const m = modules[r][c];
      if (m === modules[r][c + 1] && m === modules[r + 1][c]
          && m === modules[r + 1][c + 1]) score += 3;
    }
  }

  // N3: finder-like 1:1:3:1:1 pattern with 4 light modules on one side
  // (10111010000 / 00001011101), rows and columns.
  const P1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const P2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  for (let axis = 0; axis < 2; axis += 1) {
    for (let i = 0; i < size; i += 1) {
      for (let j = 0; j + 10 < size; j += 1) {
        let match1 = true;
        let match2 = true;
        for (let k = 0; k < 11; k += 1) {
          const m = axis === 0 ? modules[i][j + k] : modules[j + k][i];
          if (m !== (P1[k] === 1)) match1 = false;
          if (m !== (P2[k] === 1)) match2 = false;
        }
        if (match1 || match2) score += 40;
      }
    }
  }

  // N4: dark-module proportion, 10 points per 5% step away from 50%.
  let dark = 0;
  for (const rowArr of modules) for (const m of rowArr) if (m) dark += 1;
  score += Math.floor(Math.abs((dark / (size * size)) * 100 - 50) / 5) * 10;
  return score;
}

// --- public API ---------------------------------------------------------

// Encode TEXT (UTF-8) -> { version, size, mask, modules } where modules is
// a size x size array of booleans (true = dark). FORCEDMASK pins the mask
// (tests); default picks the lowest-penalty mask, lowest index on ties.
export function qrEncode(text, forcedMask) {
  const bytes = new TextEncoder().encode(text);
  const version = pickVersion(bytes.length);
  const codewords = buildCodewords(bytes, version);

  let mask = forcedMask;
  if (mask === undefined) {
    let best = Infinity;
    for (let m = 0; m < 8; m += 1) {
      const trial = baseMatrix(version);
      placeData(trial, codewords, m);
      // Format/version areas stay light during scoring, like the reference.
      const p = penalty(trial.modules);
      if (p < best) {
        best = p;
        mask = m;
      }
    }
  }

  const matrix = baseMatrix(version);
  placeData(matrix, codewords, mask);
  writeFormatAndVersion(matrix, version, mask);
  return { version, size: matrix.size, mask, modules: matrix.modules };
}

// TEXT -> a standalone SVG string (4-module quiet zone, crisp edges).
export function qrSvgString(text) {
  const { size, modules } = qrEncode(text);
  const quiet = 4;
  const total = size + 2 * quiet;
  let d = '';
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (modules[r][c]) d += `M${c + quiet} ${r + quiet}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}"`
    + ` shape-rendering="crispEdges"><rect width="${total}" height="${total}"`
    + ` fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

// TEXT -> a same-document data: URI for an <img> (no innerHTML, no fetch).
export function qrDataUri(text) {
  return `data:image/svg+xml,${encodeURIComponent(qrSvgString(text))}`;
}
