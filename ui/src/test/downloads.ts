// Files the UI saves (saveBlob: an object URL on a clicked <a download>), captured for tests.
import { vi } from "vitest";

export interface Saved {
  name: string;
  blob: Blob;
}

/** Captures every file the page saves from now on (name and content). */
export function captureDownloads(): Saved[] {
  const saved: Saved[] = [];
  const blobs = new Map<string, Blob>();
  let n = 0;
  URL.createObjectURL = vi.fn((b: Blob | MediaSource) => {
    const url = `blob:test/${n++}`;
    blobs.set(url, b as Blob);
    return url;
  });
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    const blob = blobs.get(this.href);
    if (blob) saved.push({ name: this.download, blob });
  });
  return saved;
}

/** Standard base64 to bytes (the test's own decoder, independent of the UI's). */
export function b64bytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
