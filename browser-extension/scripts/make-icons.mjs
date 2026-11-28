// Draws the extension's icons (public/icons/icon-<size>.png): a green rounded square with three
// white pickets. Run by hand when the design changes (`node scripts/make-icons.mjs`); the PNGs
// are committed, so the build needs no image tools.

import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32, deflateSync } from 'node:zlib';

const out = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public', 'icons');
/** @type {number[]} */
const BG = [31, 111, 74];
/** @type {number[]} */
const FG = [255, 255, 255];

/**
 * Coverage of the unit-square design at (x, y) in [0, 1): 0 outside, 1 background, 2 picket.
 * @param {number} x
 * @param {number} y
 */
function shape(x, y) {
  const r = 0.2;
  const cx = Math.min(Math.max(x, r), 1 - r);
  const cy = Math.min(Math.max(y, r), 1 - r);
  if ((x - cx) ** 2 + (y - cy) ** 2 > r * r) {
    return 0;
  }
  // Three pickets with pointed tops, and a rail across them.
  for (const left of [0.2, 0.425, 0.65]) {
    const w = 0.15;
    const mid = left + w / 2;
    if (x >= left && x <= left + w && y <= 0.82) {
      const top = 0.26 + Math.abs(x - mid) * 1.1;
      if (y >= top) {
        return 2;
      }
    }
  }
  if (y >= 0.56 && y <= 0.64 && x >= 0.16 && x <= 0.84) {
    return 2;
  }
  return 1;
}

/** @param {number} size */
function png(size) {
  const ss = 4;
  const rows = [];
  for (let py = 0; py < size; py++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let px = 0; px < size; px++) {
      let bg = 0;
      let fg = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const v = shape((px + (sx + 0.5) / ss) / size, (py + (sy + 0.5) / ss) / size);
          if (v === 1) bg++;
          if (v === 2) fg++;
        }
      }
      const n = ss * ss;
      const a = (bg + fg) / n;
      const o = 1 + px * 4;
      for (let c = 0; c < 3; c++) {
        row[o + c] = a === 0 ? 0 : Math.round(((BG[c] ?? 0) * bg + (FG[c] ?? 0) * fg) / (bg + fg));
      }
      row[o + 3] = Math.round(a * 255);
    }
    rows.push(row);
  }
  /** @param {string} type @param {Buffer} data */
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(Buffer.concat(rows), { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

mkdirSync(out, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  writeFileSync(path.join(out, `icon-${size}.png`), png(size));
}
console.log(`wrote ${out}`);
