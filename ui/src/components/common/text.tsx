import * as React from "react";
import { cn } from "@/lib/utils";
import { escapeControl, escapeControlKeepLines, prettyJson } from "@/lib/text";

/**
 * Text from outside core, rendered as React text with control characters escaped (core.md §12).
 * Use it for query names, client/device/edge names, rule text, verdict and alert details.
 */
export function SafeText({
  children,
  className,
  mono,
  multiline,
  title,
}: {
  children: string | null | undefined;
  className?: string;
  mono?: boolean;
  multiline?: boolean;
  title?: boolean;
}) {
  if (children === null || children === undefined || children === "") {
    return <span className={cn("text-muted-foreground", className)}>—</span>;
  }
  const text = multiline ? escapeControlKeepLines(children) : escapeControl(children);
  return (
    <span
      className={cn(mono && "font-mono text-[0.85em]", multiline && "whitespace-pre-wrap", "break-words", className)}
      title={title ? text : undefined}
    >
      {text}
    </span>
  );
}

/** JSON detail (alert details, events) as escaped, pretty-printed text. */
export function JsonBlock({ value, className }: { value: unknown; className?: string }) {
  if (value === null || value === undefined) return <span className="text-muted-foreground">—</span>;
  return (
    <pre className={cn("max-h-96 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-words", className)}>
      {prettyJson(value)}
    </pre>
  );
}

/**
 * Core's own help text (OpenAPI descriptions, spec wording) with `code` spans rendered as
 * <code>. Still React text only: nothing is parsed as HTML.
 */
export function RichText({ text, className }: { text: string | undefined; className?: string }) {
  if (!text) return null;
  const parts = text.split(/(`[^`]+`)/g);
  return (
    <span className={className}>
      {parts.map((p, i) =>
        p.startsWith("`") && p.endsWith("`") && p.length > 2 ? (
          <code key={i} className="rounded bg-muted px-1 py-px font-mono text-[0.85em]">
            {p.slice(1, -1)}
          </code>
        ) : (
          <React.Fragment key={i}>{p.replace(/\*\*/g, "")}</React.Fragment>
        ),
      )}
    </span>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <code className={cn("font-mono text-[0.85em]", className)}>{children}</code>;
}
