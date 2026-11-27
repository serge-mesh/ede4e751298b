import { InfoIcon } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { RichText } from "./text";
import { cn } from "@/lib/utils";

/** An info icon whose tooltip is a field description (from the OpenAPI document). */
export function InfoTip({ text, className, label = "More information" }: { text?: string; className?: string; label?: string }) {
  if (!text) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className={cn("inline-flex text-muted-foreground hover:text-foreground focus-visible:text-foreground", className)}
          aria-label={label}
        >
          <InfoIcon className="size-3.5" />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm text-left">
        <RichText text={text} />
      </TooltipContent>
    </Tooltip>
  );
}
