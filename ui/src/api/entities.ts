// Generic CRUD for the configuration entities of core.md §2 (api.md §7: REST CRUD per entity).
import { client, request, unwrap } from "./http";
import type {
  BundleDef,
  ClientDef,
  FeedDef,
  FeedProviderDef,
  ForwardZoneDef,
  ListenerDef,
  LookupProviderDef,
  Outcome,
  Page,
  ProfileDef,
  UpstreamDef,
  UpstreamGroupDef,
} from "./types";

export interface EntityTypes {
  clients: ClientDef;
  listeners: ListenerDef;
  profiles: ProfileDef;
  upstreams: UpstreamDef;
  "upstream-groups": UpstreamGroupDef;
  "forward-zones": ForwardZoneDef;
  "feed-providers": FeedProviderDef;
  feeds: FeedDef;
  bundles: BundleDef;
  "lookup-providers": LookupProviderDef;
}

export type EntityKind = keyof EntityTypes;

/** The OpenAPI component of each entity, for schema-driven forms. */
export const ENTITY_SCHEMA: Record<EntityKind, string> = {
  clients: "ClientDef",
  listeners: "ListenerDef",
  profiles: "ProfileDef",
  upstreams: "UpstreamDef",
  "upstream-groups": "UpstreamGroupDef",
  "forward-zones": "ForwardZoneDef",
  "feed-providers": "FeedProviderDef",
  feeds: "FeedDef",
  bundles: "BundleDef",
  "lookup-providers": "LookupProviderDef",
};

export const ENTITY_LABEL: Record<EntityKind, string> = {
  clients: "client",
  listeners: "listener",
  profiles: "profile",
  upstreams: "upstream",
  "upstream-groups": "upstream group",
  "forward-zones": "forward zone",
  "feed-providers": "feed provider",
  feeds: "feed",
  bundles: "bundle",
  "lookup-providers": "lookup provider",
};

/** The key an entity is addressed by in `/{kind}/{id}` (clients by name). */
export function entityId<K extends EntityKind>(kind: K, e: EntityTypes[K]): string {
  if (kind === "clients") return (e as ClientDef).name ?? "";
  return (e as { id?: string }).id ?? "";
}

/** Most pages fetched for one list (500 items each): bounded. */
const MAX_PAGES = 40;

/** Every item of a cursor-paginated list. */
export async function fetchAllPages<T>(fetchPage: (cursor?: string) => Promise<Page<T>>): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await fetchPage(cursor);
    out.push(...page.items);
    if (!page.next_cursor) break;
    cursor = page.next_cursor;
  }
  return out;
}

export async function listEntities<K extends EntityKind>(kind: K, signal?: AbortSignal): Promise<EntityTypes[K][]> {
  return fetchAllPages((cursor) =>
    unwrap(
      client.GET(`/api/ui/v1/${kind}` as "/api/ui/v1/profiles", {
        params: { query: { cursor, limit: 500 } },
        signal,
      }),
    ) as unknown as Promise<Page<EntityTypes[K]>>,
  );
}

export async function getEntity<K extends EntityKind>(kind: K, id: string, signal?: AbortSignal): Promise<EntityTypes[K]> {
  return unwrap(
    client.GET(`/api/ui/v1/${kind}/{id}` as "/api/ui/v1/profiles/{id}", { params: { path: { id } }, signal }),
  ) as unknown as Promise<EntityTypes[K]>;
}

export async function createEntity<K extends EntityKind>(kind: K, body: EntityTypes[K]): Promise<Outcome> {
  return unwrap(
    client.POST(`/api/ui/v1/${kind}` as "/api/ui/v1/profiles", { body: body as ProfileDef }),
  ) as unknown as Promise<Outcome>;
}

export interface SaveFlags {
  clear_cached_verdicts?: boolean;
  delete_unselected?: boolean;
}

export async function updateEntity<K extends EntityKind>(
  kind: K,
  id: string,
  body: EntityTypes[K],
  flags: SaveFlags = {},
): Promise<Outcome> {
  return request<Outcome>("PUT", `/${kind}/${encodeURIComponent(id)}`, {
    body,
    query: { ...flags },
  });
}

export async function deleteEntity(kind: EntityKind, id: string): Promise<Outcome> {
  return unwrap(
    client.DELETE(`/api/ui/v1/${kind}/{id}` as "/api/ui/v1/profiles/{id}", { params: { path: { id } } }),
  ) as unknown as Promise<Outcome>;
}
