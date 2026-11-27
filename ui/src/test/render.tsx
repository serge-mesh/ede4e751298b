import { render } from "@testing-library/react";
import { createMemoryHistory } from "@tanstack/react-router";
import { App } from "@/app";
import { createAppRouter } from "@/router";
import { makeQueryClient } from "@/lib/query-client";

/**
 * Renders the whole app (router, query client, providers) at a path. Queries don't retry unless
 * `retry` asks for the app's own rule (lib/query-client.ts).
 */
export function renderApp(path = "/", opts: { retry?: boolean } = {}) {
  const queryClient = makeQueryClient({ retry: opts.retry ?? false });
  const router = createAppRouter(queryClient, createMemoryHistory({ initialEntries: [path] }));
  const utils = render(<App queryClient={queryClient} router={router} />);
  return { ...utils, router, queryClient };
}
