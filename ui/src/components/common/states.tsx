import * as React from "react";
import { AlertTriangleIcon, ClockIcon, InboxIcon, RefreshCwIcon } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { errorMessage, isNotAvailable } from "@/api/errors";
import { cn } from "@/lib/utils";

export function LoadingState({ rows = 3, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)} role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
      <span className="sr-only">Loading…</span>
    </div>
  );
}

export function EmptyState({
  title,
  children,
  action,
  className,
}: {
  title: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-8 text-center", className)}>
      <InboxIcon className="size-6 text-muted-foreground" aria-hidden />
      <p className="font-medium">{title}</p>
      {children && <div className="max-w-md text-sm text-muted-foreground">{children}</div>}
      {action}
    </div>
  );
}

/** Shown while core answers an endpoint with 404 (not built) or 501: it lights up later. */
export function NotAvailable({ what, children, className }: { what: string; children?: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn("flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-6 text-center", className)}
      data-testid="not-available"
    >
      <ClockIcon className="size-5 text-muted-foreground" aria-hidden />
      <p className="text-sm font-medium">{what}: not available yet</p>
      <p className="max-w-md text-xs text-muted-foreground">
        {children ?? "This version of picket-core doesn't provide it yet. It appears here once core does."}
      </p>
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  return (
    <div role="alert" data-testid="error-state" className={cn("flex flex-col items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-6 text-center", className)}>
      <AlertTriangleIcon className="size-5 text-destructive" aria-hidden />
      <p className="text-sm font-medium text-destructive">{errorMessage(error)}</p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCwIcon /> Retry
        </Button>
      )}
    </div>
  );
}

/**
 * A refetch of data still shown failed: the data stays, and with it any draft a form or editor
 * built on it (core.md §12: an edit is never lost to a failed read); this says what failed, with
 * Retry.
 */
export function RefetchError({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  return (
    <div role="alert" data-testid="refetch-error" className={cn("flex flex-wrap items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm", className)}>
      <AlertTriangleIcon className="size-4 shrink-0 text-destructive" aria-hidden />
      <span className="text-destructive">Couldn't refresh: {errorMessage(error)}. What's shown may be out of date.</span>
      {onRetry && (
        <Button variant="outline" size="sm" className="ml-auto" onClick={onRetry}>
          <RefreshCwIcon /> Retry
        </Button>
      )}
    </div>
  );
}

/** A list read a page at a time with "Load more" (useInfiniteQuery). */
interface PagedLike {
  error: unknown;
  isFetchNextPageError: boolean;
  refetch: () => unknown;
  fetchNextPage: () => unknown;
}

/**
 * A paged list's errors once it shows rows: the rows stay. A failed refresh shows above them
 * (`RefetchError`, Retry reads every loaded page again); a failed "Load more" shows below them,
 * with Retry for that page only (`placement` picks which this one renders).
 */
export function PagedListError({ query, placement, what }: { query: PagedLike; placement: "top" | "bottom"; what: string }) {
  if (!query.error) return null;
  if (!query.isFetchNextPageError) return placement === "top" ? <RefetchError error={query.error} onRetry={() => void query.refetch()} /> : null;
  if (placement !== "bottom") return null;
  return (
    <div role="alert" data-testid="next-page-error" className="flex flex-wrap items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm">
      <AlertTriangleIcon className="size-4 shrink-0 text-destructive" aria-hidden />
      <span className="text-destructive">
        Couldn't load {what}: {errorMessage(query.error)}.
      </span>
      <Button variant="outline" size="sm" className="ml-auto" onClick={() => void query.fetchNextPage()}>
        <RefreshCwIcon /> Retry
      </Button>
    </div>
  );
}

interface QueryLike<T> {
  data: T | undefined;
  error: unknown;
  isPending: boolean;
  refetch: () => unknown;
}

/**
 * Renders a query's loading, error, "not available yet" and data states uniformly. Once there is
 * data, a failed refetch keeps it (and anything built on it) and shows `RefetchError` above it.
 */
export function QueryView<T>({
  query,
  children,
  what,
  rows,
  empty,
  isEmpty,
}: {
  query: QueryLike<T>;
  children: (data: T) => React.ReactNode;
  what?: string;
  rows?: number;
  empty?: React.ReactNode;
  isEmpty?: (data: T) => boolean;
}) {
  if (query.data === undefined) {
    if (!query.error) return <LoadingState rows={rows} />;
    if (what && isNotAvailable(query.error)) return <NotAvailable what={what} />;
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  const refetchError = query.error ? <RefetchError error={query.error} onRetry={() => void query.refetch()} className="mb-2" /> : null;
  if (empty && isEmpty?.(query.data))
    return (
      <>
        {refetchError}
        {empty}
      </>
    );
  return (
    <>
      {refetchError}
      {children(query.data)}
    </>
  );
}
