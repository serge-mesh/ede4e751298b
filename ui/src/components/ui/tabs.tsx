import * as React from "react";
import { Tabs as TabsPrimitive } from "radix-ui";
import { cn } from "@/lib/utils";
import { DraftScope } from "@/components/common/drafts";

/** The tab shown now (a controlled `Tabs`' value), for `TabsContent`. */
const Shown = React.createContext<string | undefined>(undefined);

export function Tabs({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return (
    <Shown.Provider value={props.value}>
      <TabsPrimitive.Root className={cn("flex flex-col gap-3", className)} {...props} />
    </Shown.Provider>
  );
}

export function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      className={cn(
        "inline-flex h-9 w-fit max-w-full items-center justify-start overflow-x-auto rounded-lg bg-muted p-[3px] text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

export function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        "inline-flex h-[calc(100%-1px)] flex-1 items-center justify-center gap-1.5 rounded-md border border-transparent px-2.5 py-1 text-sm font-medium whitespace-nowrap text-foreground/80 transition-[color,box-shadow] focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-1 disabled:pointer-events-none disabled:opacity-50 data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm dark:data-[state=active]:border-input dark:data-[state=active]:bg-input/30 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        className,
      )}
      {...props}
    />
  );
}

/**
 * A tab's content: mounted while shown, and while a form in it holds an unsaved draft
 * (components/common/drafts.tsx `useDraft`), so the draft survives another tab showing; it is
 * hidden meanwhile.
 */
export function TabsContent({ className, value, forceMount, children, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  const shown = React.useContext(Shown);
  const [draft, setDraft] = React.useState(false);
  return (
    <TabsPrimitive.Content
      value={value}
      forceMount={forceMount ?? (draft || undefined)}
      hidden={shown === undefined ? undefined : shown !== value}
      className={cn("flex-1 outline-none", className)}
      {...props}
    >
      <DraftScope onDirty={setDraft}>{children}</DraftScope>
    </TabsPrimitive.Content>
  );
}
