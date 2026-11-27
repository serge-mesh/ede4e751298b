import { beforeEach, describe, expect, it, vi } from 'vitest';

import { TabGuard } from '../src/background/tab-guard';
import { MAX_PER_TAB, parseTabBlocks, TabStore } from '../src/background/tab-store';
import type { TabBlock } from '../src/shared/messages';
import fake, { resetFakeBrowser } from './fake-browser';

beforeEach(resetFakeBrowser);

const block = (host: string, at = 1): TabBlock => ({ host, kind: 'dns', blockId: 'abcdefgh', at });

describe('TabStore', () => {
  it("keeps each tab's hosts once, newest last, up to the cap", async () => {
    const changes = vi.fn();
    const s = new TabStore(fake.storage.session, new TabGuard(), changes);
    await s.record(1, block('a.example'));
    await s.record(1, block('b.example'));
    await s.record(1, block('a.example', 2));
    await s.record(2, block('c.example'));
    expect(await s.list(1)).toEqual([block('b.example'), block('a.example', 2)]);
    expect(await s.list(2)).toEqual([block('c.example')]);
    expect(changes).toHaveBeenLastCalledWith(2, 1);
    for (let i = 0; i < MAX_PER_TAB + 5; i++) {
      await s.record(3, block(`h${String(i)}.example`));
    }
    const list = await s.list(3);
    expect(list).toHaveLength(MAX_PER_TAB);
    expect(list[0]?.host).toBe('h5.example');
    await s.clear(1);
    expect(await s.list(1)).toEqual([]);
    expect(changes).toHaveBeenLastCalledWith(1, 0);
  });

  it('serialises concurrent changes, coalescing them into one write in flight and one waiting', async () => {
    const s = new TabStore(fake.storage.session, new TabGuard());
    await Promise.all(Array.from({ length: 20 }, (_, i) => s.record(1, block(`h${String(i)}.example`))));
    expect(await s.list(1)).toHaveLength(20);
    expect(fake.storage.session.set).toHaveBeenCalledTimes(2);
    // A request-heavy page: 1,000 failures cost a handful of writes, not 1,000 queued ones.
    fake.storage.session.set.mockClear();
    const done: Promise<void>[] = [];
    for (let i = 0; i < 1000; i++) {
      done.push(s.record(2, block(`h${String(i % 80)}.example`, i)));
    }
    await Promise.all(done);
    expect(fake.storage.session.set.mock.calls.length).toBeLessThanOrEqual(2);
    const list = await s.list(2);
    expect(list).toHaveLength(MAX_PER_TAB);
    expect(list.at(-1)).toEqual(block('h39.example', 999));
  });

  it('drops what was found on an earlier page, for a closed tab, or before allows changed', async () => {
    const guard = new TabGuard();
    const s = new TabStore(fake.storage.session, guard);
    const pageA = guard.ticket(1);
    await s.record(1, block('a.example'), pageA);
    // The tab's next page: a new navigation token, and its list starts empty.
    guard.navigated(1);
    await s.clear(1);
    const pageB = guard.ticket(1);
    await s.record(1, block('late.example'), pageA);
    await s.record(1, block('b.example'), pageB);
    expect((await s.list(1)).map((b) => b.host)).toEqual(['b.example']);
    // A clear wins over records still waiting to be written.
    void s.record(1, block('c.example'), pageB);
    await s.clear(1);
    expect(await s.list(1)).toEqual([]);
    const tab2 = guard.ticket(2);
    guard.removed(2);
    await s.remove(2);
    await s.record(2, block('gone.example'), tab2);
    expect(fake.storage.session.data.has('tab:2')).toBe(false);
    // Found before an allow changed what is blocked: not listed.
    const before = guard.ticket(3);
    guard.allowsChanged();
    await s.record(3, block('lifted.example'), before);
    await s.record(3, block('still.example'));
    expect((await s.list(3)).map((b) => b.host)).toEqual(['still.example']);
    // A ticket for another tab never lists.
    await s.record(3, block('other.example'), guard.ticket(4));
    expect((await s.list(3)).map((b) => b.host)).toEqual(['still.example']);
  });

  it('drops a host whose ticket lapsed while the writer read the stored list (recheck G4)', async () => {
    const guard = new TabGuard();
    const changes = vi.fn();
    const s = new TabStore(fake.storage.session, guard, changes);
    await s.record(3, block('first.example'));
    /** Holds the writer's next read of the stored list until `release()`. */
    const holdRead = (): (() => void) => {
      let release: () => void = () => undefined;
      const read = new Promise<void>((r) => (release = r));
      const get = fake.storage.session.get.getMockImplementation();
      fake.storage.session.get.mockImplementationOnce(async (key) => {
        await read;
        return (await get?.(key)) ?? {};
      });
      return release;
    };
    // An allow succeeds while the writer reads the list.
    let release = holdRead();
    let done = s.record(3, block('lifted.example'), guard.ticket(3));
    guard.allowsChanged();
    release();
    await done;
    // The tab moves on while the writer reads the list (its clear is a later write).
    release = holdRead();
    done = s.record(3, block('late.example'), guard.ticket(3));
    guard.navigated(3);
    release();
    await done;
    expect((await s.list(3)).map((b) => b.host)).toEqual(['first.example']);
    expect(changes.mock.calls.every(([, count]) => count === 1)).toBe(true);
    // One already stale when it comes isn't even written.
    fake.storage.session.set.mockClear();
    const stale = guard.ticket(3);
    guard.allowsChanged();
    await s.record(3, block('stale.example'), stale);
    expect(fake.storage.session.set).not.toHaveBeenCalled();
    // Control: one that still holds is listed.
    release = holdRead();
    done = s.record(3, block('still.example'), guard.ticket(3));
    release();
    await done;
    expect((await s.list(3)).map((b) => b.host)).toEqual(['first.example', 'still.example']);
  });

  it('reports a failed write to every change it carried', async () => {
    const s = new TabStore(fake.storage.session, new TabGuard());
    fake.storage.session.set.mockRejectedValueOnce(new Error('quota'));
    await expect(s.record(1, block('a.example'))).rejects.toThrow('quota');
    await s.record(1, block('b.example'));
    expect((await s.list(1)).map((b) => b.host)).toEqual(['b.example']);
  });

  it('reads back only well-formed entries', () => {
    expect(
      parseTabBlocks([
        block('ok.example'),
        { host: 'x', kind: 'other', at: 1 },
        { host: 5, kind: 'dns', at: 1 },
        { host: 'y', kind: 'ip' },
        { host: 'z', kind: 'dns', at: 1, bundle: 7 },
        null,
      ]),
    ).toEqual([block('ok.example')]);
    expect(parseTabBlocks('nope')).toEqual([]);
  });
});
