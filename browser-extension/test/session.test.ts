import { describe, expect, it, vi } from 'vitest';

import { MAX_EARLY, SessionMap, type SessionCodec } from '../src/background/session';
import { FakeArea } from './fake-browser';

const codec: SessionCodec<string> = {
  parse: (x) => (Array.isArray(x) ? (x as { tab: number; v: string }[]).map((e): [number, string] => [e.tab, e.v]) : []),
  serialize: (entries) => entries.map(([tab, v]) => ({ tab, v })),
};

async function flush(): Promise<void> {
  for (let i = 0; i < 50; i++) {
    await Promise.resolve();
  }
}

/** An area holding what a previous script left, whose next read waits for `release()`. */
function kept(entries: { tab: number; v: string }[]): { area: FakeArea; release: () => void } {
  const area = new FakeArea();
  area.data.set('k', entries);
  let release: () => void = () => undefined;
  const read = new Promise<void>((r) => (release = r));
  const get = area.get.getMockImplementation();
  area.get.mockImplementationOnce(async (key) => {
    await read;
    return (await get?.(key)) ?? {};
  });
  return { area, release };
}

describe('SessionMap (README §2 "Restarts")', () => {
  it('applies the events that come before the read to the restored map, in arrival order, writing nothing before it', async () => {
    const { area, release } = kept([
      { tab: 1, v: 'a' },
      { tab: 2, v: 'b' },
    ]);
    const seen: (string | undefined)[] = [];
    const m = new SessionMap<string>(area, 'k', codec, 16, (restored) => {
      seen.push(`restored ${restored.map(([t, v]) => `${String(t)}=${v}`).join(',')}`);
    });
    void m.whenRead(() => seen.push(m.get(1)));
    const changed = m.set(1, 'c');
    void m.whenRead(() => seen.push(m.get(1)));
    void m.delete(2);
    await flush();
    expect(m.loaded).toBe(false);
    expect(seen).toEqual([]);
    expect(area.set).not.toHaveBeenCalled();
    expect(area.remove).not.toHaveBeenCalled();
    release();
    await m.ready;
    expect(seen).toEqual(['restored 1=a,2=b', 'a', 'c']);
    await changed;
    expect(area.data.get('k')).toEqual([{ tab: 1, v: 'c' }]);
  });

  it('runs an event at once after the read', async () => {
    const m = new SessionMap<string>(new FakeArea(), 'k', codec, 16);
    await m.ready;
    let ran = false;
    void m.whenRead(() => (ran = true));
    expect(ran).toBe(true);
    await expect(
      m.whenRead(() => {
        throw new Error('bad');
      }),
    ).rejects.toThrow('bad');
  });

  it('gives the stored map up rather than hold more than MAX_EARLY events, and replaces it once read', async () => {
    for (const own of [true, false]) {
      const { area, release } = kept([{ tab: 1, v: 'a' }]);
      const restore = vi.fn();
      const m = new SessionMap<string>(area, 'k', codec, 16, restore);
      const order: number[] = [];
      for (let i = 0; i < MAX_EARLY; i++) {
        void m.whenRead(() => order.push(i));
      }
      expect(order).toEqual([]);
      void m.whenRead(() => order.push(MAX_EARLY));
      // The waiting events ran, in order, then the new one; later ones run at once.
      expect(order).toEqual([...Array(MAX_EARLY + 1).keys()]);
      expect(m.gaveUp).toBe(true);
      expect(m.loaded).toBe(true);
      expect(m.get(1)).toBeUndefined();
      if (own) {
        void m.set(2, 'b');
      }
      release();
      await m.ready;
      await flush();
      expect(restore).not.toHaveBeenCalled();
      expect(m.entries()).toEqual(own ? [[2, 'b']] : []);
      expect(area.data.get('k')).toEqual(own ? [{ tab: 2, v: 'b' }] : undefined);
    }
  });

  it('keeps at most `max` tabs, the newest, and stores again what it trimmed at start', async () => {
    const area = new FakeArea();
    area.data.set('k', [
      { tab: 1, v: 'a' },
      { tab: 2, v: 'b' },
      { tab: 3, v: 'c' },
    ]);
    const m = new SessionMap<string>(area, 'k', codec, 2);
    await m.ready;
    await flush();
    expect(area.data.get('k')).toEqual([
      { tab: 2, v: 'b' },
      { tab: 3, v: 'c' },
    ]);
    await m.set(4, 'd');
    expect(m.entries()).toEqual([
      [3, 'c'],
      [4, 'd'],
    ]);
  });
});
