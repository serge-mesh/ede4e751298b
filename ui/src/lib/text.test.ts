import { describe, expect, it } from "vitest";
import { displayValue, escapeControl, escapeControlKeepLines, prettyJson } from "./text";

describe("escapeControl (core.md §12: control characters shown escaped)", () => {
  it("escapes C0, DEL, C1 and bidi/zero-width characters", () => {
    expect(escapeControl("a\u0000b\u0007c\u007fd\u0085")).toBe("a\\x00b\\x07c\\x7fd\\x85");
    expect(escapeControl("evil‮txt.exe")).toBe("evil\\u{202e}txt.exe");
    expect(escapeControl("zero​width")).toBe("zero\\u{200b}width");
    expect(escapeControl("tab\tnew\nline\r")).toBe("tab\\tnew\\nline\\r");
  });
  it("leaves ordinary text, quotes, backslashes and markup alone (React escapes markup)", () => {
    expect(escapeControl('<img src=x onerror=alert(1)> "q" \\ ü 日本')).toBe('<img src=x onerror=alert(1)> "q" \\ ü 日本');
  });
  it("keeps line breaks where asked", () => {
    expect(escapeControlKeepLines("a\u0001\nb")).toBe("a\\x01\nb");
  });
  it("renders JSON values escaped", () => {
    expect(displayValue({ a: "‮" })).toBe('{"a":"\\u{202e}"}');
    expect(prettyJson({ a: 1 })).toBe('{\n  "a": 1\n}');
  });
});
