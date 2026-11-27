// A minimal WebDriver BiDi client (Node's built-in WebSocket) for Firefox. Playwright drives
// Firefox through Juggler, which leaves `moz-extension:` documents alone, so the tests reach the
// extension's pages, and install the extension, through Firefox's own WebDriver BiDi agent,
// which the Playwright build of Firefox includes.

import { WAIT_MS } from './time';

interface Pending {
  resolve(v: unknown): void;
  reject(e: Error): void;
}

export interface BidiContext {
  context: string;
  url: string;
  children: BidiContext[] | null;
}

export class Bidi {
  private id = 0;
  private readonly pending = new Map<number, Pending>();

  private constructor(private readonly ws: WebSocket) {
    ws.onmessage = (ev: MessageEvent<string>) => {
      const m = JSON.parse(ev.data) as { id?: number; type?: string; error?: string; message?: string; result?: unknown };
      if (m.id === undefined) {
        return;
      }
      const p = this.pending.get(m.id);
      if (p === undefined) {
        return;
      }
      this.pending.delete(m.id);
      if (m.type === 'error') {
        p.reject(new Error(`BiDi ${m.error ?? 'error'}: ${m.message ?? ''}`));
      } else {
        p.resolve(m.result);
      }
    };
    ws.onclose = () => {
      for (const p of this.pending.values()) {
        p.reject(new Error('BiDi connection closed'));
      }
      this.pending.clear();
    };
  }

  /** Connects to `ws://127.0.0.1:<port>/session`, retrying while Firefox starts its agent. */
  static async connect(port: number, timeoutMs = WAIT_MS): Promise<Bidi> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const ws = new WebSocket(`ws://127.0.0.1:${String(port)}/session`);
        await new Promise<void>((resolve, reject) => {
          ws.onopen = () => {
            resolve();
          };
          ws.onerror = () => {
            reject(new Error('WebSocket error'));
          };
        });
        return new Bidi(ws);
      } catch (e) {
        if (Date.now() > deadline) {
          throw new Error(`no WebDriver BiDi agent on port ${String(port)}`, { cause: e });
        }
        await new Promise((r) => setTimeout(r, 100));
      }
    }
  }

  send<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    this.id += 1;
    const id = this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve, reject });
    });
  }

  async tree(scope?: 'chrome'): Promise<BidiContext[]> {
    const r = await this.send<{ contexts: BidiContext[] }>('browsingContext.getTree', scope === undefined ? {} : { 'moz:scope': scope });
    return r.contexts;
  }

  /**
   * Evaluates `expression` (a promise is awaited) in a context and returns its value, which must
   * be a JSON string.
   */
  async evaluateJson<T>(context: string, expression: string): Promise<T> {
    const r = await this.send<{ type: string; result?: { type: string; value?: unknown }; exceptionDetails?: { text?: string } }>('script.evaluate', {
      expression,
      target: { context },
      awaitPromise: true,
      resultOwnership: 'none',
    });
    if (r.type === 'exception') {
      throw new Error(`evaluation failed: ${r.exceptionDetails?.text ?? 'exception'}`);
    }
    const v = r.result?.value;
    if (typeof v !== 'string') {
      throw new Error(`evaluation returned ${JSON.stringify(r.result)}`);
    }
    return JSON.parse(v) as T;
  }

  /** The shared reference of the element `selector` matches, or null. */
  async element(context: string, selector: string): Promise<string | null> {
    const r = await this.send<{ type: string; result?: { type: string; sharedId?: string } }>('script.evaluate', {
      expression: `document.querySelector(${JSON.stringify(selector)})`,
      target: { context },
      awaitPromise: false,
      resultOwnership: 'none',
    });
    return r.type === 'success' && r.result?.type === 'node' && r.result.sharedId !== undefined ? r.result.sharedId : null;
  }

  /** A real mouse click at the element's centre (trusted input, with user activation). */
  async click(context: string, sharedId: string): Promise<void> {
    await this.send('input.performActions', {
      context,
      actions: [
        {
          type: 'pointer',
          id: 'mouse',
          parameters: { pointerType: 'mouse' },
          actions: [
            { type: 'pointerMove', x: 0, y: 0, origin: { type: 'element', element: { sharedId } } },
            { type: 'pointerDown', button: 0 },
            { type: 'pointerUp', button: 0 },
          ],
        },
      ],
    });
    // The click may have closed the page (the popup closes itself after Reload page).
    await this.send('input.releaseActions', { context }).catch((e: unknown) => {
      if (!String(e).includes('no such frame')) {
        throw e;
      }
    });
  }

  close(): void {
    this.ws.close();
  }
}
