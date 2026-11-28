import { inflateRawSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { zip } from '../scripts/zip.mjs';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Reads a ZIP's entries back through its central directory. */
function unzip(buf: Buffer): { name: string; data: string; mode: number; time: number }[] {
  const end = buf.length - 22;
  expect(buf.readUInt32LE(end)).toBe(0x06054b50);
  const count = buf.readUInt16LE(end + 10);
  let p = buf.readUInt32LE(end + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    expect(buf.readUInt32LE(p)).toBe(0x02014b50);
    const method = buf.readUInt16LE(p + 10);
    const time = buf.readUInt16LE(p + 12);
    const size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const mode = buf.readUInt32LE(p + 38) >>> 16;
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    const dataStart = local + 30 + buf.readUInt16LE(local + 26);
    const raw = buf.subarray(dataStart, dataStart + size);
    out.push({ name, data: (method === 8 ? inflateRawSync(raw) : raw).toString('utf8'), mode, time });
    p += 46 + nameLen;
  }
  return out;
}

describe('zip', () => {
  const files = [
    { name: 'manifest.json', data: enc('{"a":1}') },
    { name: 'assets/big.js', data: enc('x'.repeat(10_000)) },
    { name: 'a.txt', data: enc('') },
  ];

  it('is reproducible: same files, same bytes, whatever their order', () => {
    const a = zip(files, 1767225600);
    const b = zip([...files].reverse(), 1767225600);
    expect(Buffer.compare(a, b)).toBe(0);
    expect(Buffer.compare(a, zip(files, 1767225600 + 86_400))).not.toBe(0);
  });

  it('holds every file, sorted, compressed when that helps, mode 0644', () => {
    const entries = unzip(zip(files, 1767225600));
    expect(entries.map((e) => e.name)).toEqual(['a.txt', 'assets/big.js', 'manifest.json']);
    expect(entries.map((e) => e.data)).toEqual(['', 'x'.repeat(10_000), '{"a":1}']);
    expect(entries.every((e) => e.mode === 0o100644)).toBe(true);
    expect(new Set(entries.map((e) => e.time)).size).toBe(1);
  });

  it('refuses paths that would escape the folder', () => {
    expect(() => zip([{ name: '../x', data: enc('') }])).toThrow();
    expect(() => zip([{ name: '/abs', data: enc('') }])).toThrow();
  });
});
