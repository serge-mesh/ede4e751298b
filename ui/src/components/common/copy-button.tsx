import * as React from "react";
import { CheckIcon, CopyIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function CopyButton({ value, label = "Copy", className }: { value: string; label?: string; className?: string }) {
  const [done, setDone] = React.useState(false);
  React.useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1500);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon-sm"
          className={className}
          aria-label={label}
          onClick={async () => {
            if (await copyText(value)) setDone(true);
            else toast.error("Couldn't copy: the browser blocked clipboard access.");
          }}
        >
          {done ? <CheckIcon className="text-success" /> : <CopyIcon />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{done ? "Copied" : label}</TooltipContent>
    </Tooltip>
  );
}

/** A value shown in mono with a copy button (DoH URLs, DoT names, fingerprints, list URLs). */
export function CopyField({ value, label }: { value: string; label?: string }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1">
      <code className="min-w-0 truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs" title={value}>
        {value}
      </code>
      <CopyButton value={value} label={label ?? "Copy"} />
    </span>
  );
}
