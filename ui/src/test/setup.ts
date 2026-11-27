import "@testing-library/jest-dom/vitest";
import { Blob as NodeBlob, File as NodeFile } from "node:buffer";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import { noteViolations, takeViolations } from "./mock-api";
import { eventViolations } from "./contract";

// jsdom's Blob and File lack text(), slice().text() and stream(), and Node's fetch can't send them
// as a request body; browsers have all of these, and so do Node's own Blob and File.
globalThis.Blob = NodeBlob as unknown as typeof Blob;
globalThis.File = NodeFile as unknown as typeof File;

afterEach(() => {
  cleanup();
  const refused = takeViolations();
  if (refused.length) throw new Error(`The UI sent requests core would refuse (test/contract.ts):\n${[...new Set(refused)].join("\n")}`);
});

// Node's fetch Request needs absolute URLs and rejects jsdom's AbortSignal; the UI uses relative
// URLs (same origin). Resolve URLs the way a browser would and leave cancellation out of tests.
const NativeRequest = globalThis.Request;
class BrowserLikeRequest extends NativeRequest {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    if (typeof input === "string" && input.startsWith("/")) input = new URL(input, window.location.origin).toString();
    if (init?.signal) {
      const { signal: _drop, ...rest } = init;
      init = rest;
    }
    super(input, init);
  }
}
globalThis.Request = BrowserLikeRequest as typeof Request;

// A WebSocket that never connects; tests drive it through FakeWebSocket.instances.
export class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  url: string;
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((m: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
  close() {
    this.readyState = 3;
  }
  send() {}
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  /** Delivers a frame; one core wouldn't send in that shape fails the test (test/contract.ts `eventViolations`). */
  emit(data: unknown) {
    if (typeof data !== "string") noteViolations(eventViolations(data));
    this.onmessage?.({ data: typeof data === "string" ? data : JSON.stringify(data) });
  }
}
globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;

// jsdom lacks these browser APIs that Radix, Recharts and CodeMirror use.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;
window.matchMedia ??= ((query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addEventListener: () => {},
  removeEventListener: () => {},
  addListener: () => {},
  removeListener: () => {},
  dispatchEvent: () => false,
})) as unknown as typeof window.matchMedia;
Element.prototype.scrollIntoView ??= vi.fn();
Element.prototype.hasPointerCapture ??= () => false;
Element.prototype.releasePointerCapture ??= () => {};
Element.prototype.setPointerCapture ??= () => {};
const rect = () => ({ x: 0, y: 0, top: 0, left: 0, bottom: 0, right: 0, width: 0, height: 0, toJSON: () => ({}) }) as DOMRect;
Range.prototype.getBoundingClientRect ??= rect;
Range.prototype.getClientRects ??= () => ({ length: 0, item: () => null, [Symbol.iterator]: [][Symbol.iterator] }) as unknown as DOMRectList;
document.elementFromPoint ??= () => null;
