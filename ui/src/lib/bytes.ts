// Binary data core sends as base64 (DNS wires in log details and alert evidence) and saving it
// as a file (Download as fuzz case, an answer's or reply's wire).
import { saveBlob } from "@/api/http";

/** Decodes base64 as core writes it (standard alphabet, padded) to bytes; null when it isn't base64. */
export function decodeBase64(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Saves base64 `b64` as the binary file `name` (nothing when it isn't base64). */
export function saveBase64(b64: string | null | undefined, name: string) {
  const bytes = b64 ? decodeBase64(b64) : null;
  if (bytes) saveBlob(new Blob([bytes.slice().buffer], { type: "application/octet-stream" }), name);
}

/** Saves `value` as a pretty-printed JSON file. */
export function saveJson(value: unknown, name: string) {
  saveBlob(new Blob([JSON.stringify(value, null, 2) + "\n"], { type: "application/json" }), name);
}
