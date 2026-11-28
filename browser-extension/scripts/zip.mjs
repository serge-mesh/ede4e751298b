// A minimal, reproducible ZIP writer for the extension packages (build-and-test.md §3;
// security.md §6 reproducible builds): entries sorted by path, one fixed timestamp
// (SOURCE_DATE_EPOCH, else 2026-01-01), fixed permissions, deflate at level 9 (stored when that
// doesn't shrink a file), no directory entries and no extra fields.

import { crc32, deflateRawSync } from 'node:zlib';

/** @param {number} unixS */
function dosTime(unixS) {
  const d = new Date(Math.max(unixS, 315532800) * 1000); // DOS time starts in 1980
  const time = (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1);
  const date = ((d.getUTCFullYear() - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  return { time, date };
}

/** The timestamp every entry carries. */
export function zipEpoch() {
  const env = process.env['SOURCE_DATE_EPOCH'];
  return env !== undefined && /^\d+$/.test(env) ? Number(env) : 1767225600;
}

/**
 * @param {{ name: string, data: Uint8Array }[]} entries paths use `/`
 * @param {number} [epoch]
 * @returns {Buffer}
 */
export function zip(entries, epoch = zipEpoch()) {
  const { time, date } = dosTime(epoch);
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  /** @type {Buffer[]} */
  const locals = [];
  /** @type {Buffer[]} */
  const centrals = [];
  let offset = 0;
  for (const e of sorted) {
    if (e.name.startsWith('/') || e.name.includes('..') || e.name.includes('\\')) {
      throw new Error(`bad entry name: ${e.name}`);
    }
    const name = Buffer.from(e.name, 'utf8');
    const raw = Buffer.from(e.data);
    const deflated = deflateRawSync(raw, { level: 9 });
    const stored = deflated.length >= raw.length;
    const body = stored ? raw : deflated;
    const method = stored ? 0 : 8;
    const crc = crc32(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4); // made by: Unix, 2.0
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38); // -rw-r--r--
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += local.length + name.length + body.length;
    if (offset > 0xffffffff) {
      throw new Error('archive too large');
    }
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(sorted.length, 8);
  end.writeUInt16LE(sorted.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}
