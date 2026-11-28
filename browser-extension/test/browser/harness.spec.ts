// The harness cleans up after itself: a browser launch that fails leaves no profile behind, and
// a dropper that fails to start leaves no stopped process.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { launch } from './harness/browsers';
import { expect, test } from './harness/fixtures';
import { startDroppers } from './harness/targets';
import { scaled } from './harness/time';

test('a launch that fails removes its profile', async ({ kind, certs, edge, targets }) => {
  test.setTimeout(scaled(60_000));
  // Profiles go to os.tmpdir(), which follows TMPDIR: a directory of this test's own.
  const dir = mkdtempSync(path.join(tmpdir(), 'picket-harness-'));
  const saved = process.env.TMPDIR;
  process.env.TMPDIR = dir;
  try {
    const missing = path.join(dir, 'no-such-extension');
    await expect(launch({ kind, extensionDir: missing, certs, dohUrl: edge.dohUrl, markerUrl: targets.url('marker.test', '/marker') })).rejects.toThrow();
    expect(readdirSync(dir)).toEqual([]);
  } finally {
    if (saved === undefined) {
      delete process.env.TMPDIR;
    } else {
      process.env.TMPDIR = saved;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

test('droppers that fail to start leave no stopped listener', async ({ kind }) => {
  test.skip(kind !== 'chromium', 'not about a browser: once is enough');
  const stopped = (): string[] => {
    try {
      return execFileSync('pgrep', ['-f', "process.kill\\(process.pid, 'SIGSTOP'\\)"], { encoding: 'utf8' }).trim().split('\n').filter((l) => l !== '');
    } catch {
      return [];
    }
  };
  const before = stopped();
  // 192.0.2.1 (TEST-NET-1) isn't this machine's: the second listener can't bind.
  await expect(startDroppers(['127.0.0.1', '192.0.2.1'])).rejects.toThrow();
  await expect.poll(() => stopped().filter((p) => !before.includes(p))).toEqual([]);
});
