// What a tab-changing action was decided under (browser-extension.md §3 step 3: "unless the tab
// has started another navigation since"). Every action that changes a tab or what it lists
// (opening the block page, a reload after an allow, listing a blocked host) takes a ticket when
// it decides, and checks it again right before it acts, after its last await:
//
// - the tab's navigation token, which every top-level navigation in the tab replaces, and which
//   a closed tab loses;
// - the allow epoch, which every change to this device's allows replaces: a probe answered before
//   it may report a block an allow has since lifted.
//
// Both live in memory only and change synchronously as the events arrive, so a check never waits
// on storage. Tokens are unique across tabs and only ever compared.

export interface Ticket {
  readonly tabId: number;
  readonly nav: number;
  readonly epoch: number;
}

export class TabGuard {
  private readonly navs = new Map<number, number>();
  private last = 0;
  private allowEpoch = 0;

  /** The tab's current navigation token (one is made for a tab not seen since start). */
  nav(tabId: number): number {
    let n = this.navs.get(tabId);
    if (n === undefined) {
      n = ++this.last;
      this.navs.set(tabId, n);
    }
    return n;
  }

  /** A top-level navigation started in the tab; its new token. */
  navigated(tabId: number): number {
    const n = ++this.last;
    this.navs.set(tabId, n);
    return n;
  }

  /** The tab closed: no ticket for it holds again. */
  removed(tabId: number): void {
    this.navs.delete(tabId);
  }

  /** This device's allows changed. */
  allowsChanged(): void {
    this.allowEpoch += 1;
  }

  get epoch(): number {
    return this.allowEpoch;
  }

  /** A ticket for the tab as it is now (or with the token and epoch a decision was made under). */
  ticket(tabId: number, nav: number = this.nav(tabId), epoch: number = this.allowEpoch): Ticket {
    return { tabId, nav, epoch };
  }

  /** True while neither the tab's navigation nor the allows have changed since the ticket. */
  holds(t: Ticket): boolean {
    return this.navs.get(t.tabId) === t.nav && this.allowEpoch === t.epoch;
  }
}
