import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  lazyRouteComponent,
  type RouterHistory,
} from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/layout/app-shell";
import { NotFoundPage } from "@/pages/not-found";
import { parseDeviceSearch, parseProviderSearch, parseQueryLogSearch, parseTabSearch, parseWindowSearch } from "@/lib/search";

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: () => <AppShell />,
  notFoundComponent: NotFoundPage,
});

const r = (path: string, load: () => Promise<Record<string, unknown>>, name: string, validateSearch?: (s: Record<string, unknown>) => object) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path,
    component: lazyRouteComponent(load as never, name as never),
    validateSearch,
  });

const routes = [
  r("/", () => import("@/pages/dashboard"), "DashboardPage", parseWindowSearch),
  r("/query-log", () => import("@/pages/query-log"), "QueryLogPage", parseQueryLogSearch),
  r("/alerts", () => import("@/pages/alerts"), "AlertsPage"),
  r("/alerts/$alertId", () => import("@/pages/alerts"), "AlertDetailPage"),
  r("/edges", () => import("@/pages/edges"), "EdgesPage"),
  r("/edges/$edgeId", () => import("@/pages/edge-detail"), "EdgeDetailPage", (s) => ({ ...parseWindowSearch(s), ...parseTabSearch(s) })),
  r("/listeners", () => import("@/pages/listeners"), "ListenersPage"),
  r("/clients", () => import("@/pages/clients"), "ClientsPage", parseWindowSearch),
  // A device view: `?key=` (what the UI links, kept for bookmarks) or the device in the path; core
  // serves the UI document for both, dots and all (assets.rs `is_asset_path`).
  r("/clients/device", () => import("@/pages/clients"), "DeviceViewPage", parseDeviceSearch),
  r("/clients/device/$device", () => import("@/pages/clients"), "DeviceViewPage", parseWindowSearch),
  r("/clients/profile/$profileId", () => import("@/pages/clients"), "ProfileDevicesPage", parseWindowSearch),
  r("/profiles", () => import("@/pages/profiles"), "ProfilesPage"),
  r("/profiles/new", () => import("@/pages/profiles"), "NewProfilePage"),
  r("/profiles/$profileId", () => import("@/pages/profiles"), "ProfileDetailPage", parseTabSearch),
  r("/profiles/$profileId/trial/$bundleId", () => import("@/pages/trial-bundle"), "TrialBundlePage", parseWindowSearch),
  r("/upstreams", () => import("@/pages/upstreams"), "UpstreamsPage", parseTabSearch),
  r("/temporary-allows", () => import("@/pages/temporary-allows"), "TemporaryAllowsPage"),
  r("/feed-providers", () => import("@/pages/feed-providers"), "FeedProvidersPage"),
  r("/feed-providers/$providerId", () => import("@/pages/feed-provider-detail"), "FeedProviderDetailPage", parseProviderSearch),
  r("/feeds", () => import("@/pages/feeds"), "FeedsPage"),
  r("/feeds/$feedId", () => import("@/pages/feed-detail"), "FeedDetailPage", parseTabSearch),
  r("/bundles", () => import("@/pages/bundles"), "BundlesPage"),
  r("/bundles/$bundleId", () => import("@/pages/bundle-detail"), "BundleDetailPage", parseTabSearch),
  r("/warninglists", () => import("@/pages/warninglists"), "WarninglistsPage"),
  r("/lookup-providers", () => import("@/pages/lookup-providers"), "LookupProvidersPage"),
  r("/lookup-providers/$providerId", () => import("@/pages/lookup-providers"), "LookupProviderDetailPage", (s) => ({ ...parseWindowSearch(s), ...parseTabSearch(s) })),
  r("/dnssec", () => import("@/pages/dnssec"), "DnssecPage", parseWindowSearch),
  r("/system", () => import("@/pages/system"), "SystemPage", parseWindowSearch),
  r("/extension", () => import("@/pages/extension"), "ExtensionPage"),
  r("/settings", () => import("@/pages/settings"), "SettingsPage", parseTabSearch),
];

export const routeTree = rootRoute.addChildren(routes);

export function createAppRouter(queryClient: QueryClient, history?: RouterHistory) {
  return createRouter({
    routeTree,
    context: { queryClient },
    history,
    defaultPreload: "intent",
    scrollRestoration: true,
  });
}
