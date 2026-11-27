import * as React from "react";
import { formatRelative, formatTime } from "@/lib/format";

function useNow(intervalMs = 30_000) {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

/** A relative time ("5 min ago") with the absolute time as its title. */
export function TimeAgo({ value, className }: { value: string | number | null | undefined; className?: string }) {
  const now = useNow();
  if (value === null || value === undefined || value === "") return <span className="text-muted-foreground">—</span>;
  return (
    <time className={className} dateTime={typeof value === "string" ? value : undefined} title={formatTime(value)}>
      {formatRelative(value, now)}
    </time>
  );
}
