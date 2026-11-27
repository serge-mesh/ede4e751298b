import * as React from "react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { MenuIcon, MonitorIcon, MoonIcon, RefreshCwIcon, SunIcon, TriangleAlertIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useEventStream, type ConnectionState } from "@/api/events";
import { useIdentity, useOpenAlerts } from "@/api/queries";
import { page } from "@/lib/page";
import { escapeControl } from "@/lib/text";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { NAV } from "./nav";

function NavLinks({ onNavigate, openAlerts }: { onNavigate?: () => void; openAlerts?: number }) {
  const path = useRouterState({ select: (s) => s.location.pathname });
  return (
    <nav aria-label="Main" className="space-y-5">
      {NAV.map((g) => (
        <div key={g.group}>
          <div className="mb-1 px-3 text-xs font-semibold tracking-wide text-muted-foreground uppercase">{g.group}</div>
          <ul className="space-y-0.5">
            {g.items.map((it) => {
              const active = it.to === "/" ? path === "/" : path === it.to || path.startsWith(`${it.to}/`);
              return (
                <li key={it.to}>
                  <Link
                    to={it.to}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm text-sidebar-foreground transition-colors hover:bg-sidebar-accent",
                      active && "bg-sidebar-accent font-medium text-foreground",
                    )}
                  >
                    <it.icon className="size-4 shrink-0" aria-hidden />
                    <span className="truncate">{it.label}</span>
                    {it.to === "/alerts" && openAlerts ? (
                      <span className="ml-auto rounded-full bg-destructive px-1.5 text-[0.7rem] font-semibold text-white" aria-label={`${openAlerts} open alerts`}>
                        {openAlerts > 99 ? "99+" : openAlerts}
                      </span>
                    ) : null}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function ThemeMenu() {
  const { choice, setChoice } = useTheme();
  const Icon = choice === "dark" ? MoonIcon : choice === "light" ? SunIcon : MonitorIcon;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Theme">
          <Icon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => setChoice("light")}>
          <SunIcon /> Light
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => setChoice("dark")}>
          <MoonIcon /> Dark
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => setChoice("system")}>
          <MonitorIcon /> System
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function LiveIndicator({ state }: { state: ConnectionState }) {
  const text = state === "open" ? "Live updates on" : state === "connecting" ? "Connecting to live updates…" : "Live updates off: reconnecting";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground" role="status" aria-label={text}>
          <span
            className={cn(
              "size-2 rounded-full",
              state === "open" ? "bg-success" : state === "connecting" ? "animate-pulse bg-warning" : "bg-destructive",
            )}
          />
          <span className="hidden sm:inline">{state === "open" ? "Live" : state === "connecting" ? "Connecting" : "Offline"}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>{text}</TooltipContent>
    </Tooltip>
  );
}

/**
 * Core's version now and the one this page loaded with (its first identity read), when they
 * differ: a page loaded before a core upgrade may not understand the new core's events and answers
 * (README §2 Compatibility) and would quietly stop refreshing. Core's identity is read again each
 * time the event socket opens (a reconnect reads everything; the first open, READ_ON_OPEN).
 */
function useCoreUpdate(version: string | undefined): { from: string; to: string } | null {
  const [loadedWith, setLoadedWith] = React.useState<string | null>(null);
  if (version === undefined) return null;
  if (loadedWith === null) {
    setLoadedWith(version);
    return null;
  }
  return loadedWith === version ? null : { from: loadedWith, to: version };
}

export function AppShell({ children }: { children?: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  const live = useEventStream();
  const identity = useIdentity();
  const update = useCoreUpdate(identity.data?.version);
  const alerts = useOpenAlerts();
  const openCount = alerts.data?.length;
  return (
    <div className="flex min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-background focus:p-2">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 overflow-y-auto border-r bg-sidebar px-2 py-4 lg:block">
        <Link to="/" className="mb-5 flex items-center gap-2 px-3 font-semibold">
          <img src="/favicon.svg" alt="" className="size-6" /> Picket
        </Link>
        <NavLinks openAlerts={openCount} />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-12 items-center gap-2 border-b bg-background/95 px-3 backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-5">
          <Sheet open={open} onOpenChange={setOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon-sm" className="lg:hidden" aria-label="Open navigation">
                <MenuIcon />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 bg-sidebar px-2 py-4">
              <SheetTitle className="mb-4 px-3">Picket</SheetTitle>
              <NavLinks onNavigate={() => setOpen(false)} openAlerts={openCount} />
            </SheetContent>
          </Sheet>
          <span className="font-semibold lg:hidden">Picket</span>
          <div className="ml-auto flex items-center gap-3">
            {identity.data && (
              <span className="hidden text-xs text-muted-foreground md:inline">core {identity.data.version}</span>
            )}
            <LiveIndicator state={live} />
            <ThemeMenu />
          </div>
        </header>
        {update && (
          // Persistent, and never a reload by itself: the page may hold drafts.
          <div role="alert" className="flex flex-wrap items-center gap-2 border-b border-primary/40 bg-primary/10 px-5 py-2 text-sm">
            <RefreshCwIcon className="size-4 shrink-0 text-primary" aria-hidden />
            <span>{`Picket was updated (${escapeControl(update.from)} → ${escapeControl(update.to)}). Reload to use the new version.`}</span>
            <Button size="sm" variant="outline" className="ml-auto" onClick={() => page.reload()}>
              Reload
            </Button>
          </div>
        )}
        {identity.data?.plain_http && (
          <div role="alert" className="flex items-center gap-2 border-b border-warning/60 bg-warning/15 px-5 py-2 text-sm">
            <TriangleAlertIcon className="size-4 shrink-0 text-warning" aria-hidden />
            <span>
              <strong>web.tls is off:</strong> the admin password and everything on this page cross the network in clear. Turn
              TLS on under <Link to="/settings" className="underline">Settings</Link>.
            </span>
          </div>
        )}
        <main id="main" className="mx-auto w-full max-w-[1600px] min-w-0 flex-1 p-3 sm:p-5">
          {children ?? <Outlet />}
        </main>
      </div>
    </div>
  );
}
