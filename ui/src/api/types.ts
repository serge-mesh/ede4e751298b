import type { components, operations } from "./schema";

type S = components["schemas"];

/** An operation's query parameters as core's OpenAPI document types them (enums included). */
export type QueryParams<O extends keyof operations> = NonNullable<operations[O]["parameters"]["query"]>;

export type Alert = S["Alert"];
export type AlertDetail = S["AlertDetail"];
export type BundleDef = S["BundleDef"];
export type BundleFeed = S["BundleFeed"];
export type BundleStatus = S["BundleStatus"];
export type BundleDetail = S["BundleDetail"];
export type BrowserListView = S["ListView"];
export type Chart = S["Chart"];
export type ChartLine = S["Line"];
export type CheckView = S["CheckView"];
export type ClientDef = S["ClientDef"];
export type ConfigChange = S["ConfigChange"];
export type EdgeDef = S["EdgeDef"];
export type EdgeView = S["EdgeView"];
export type EdgeStatusView = S["EdgeStatusView"];
export type EntryView = S["EntryView"];
export type FeedDef = S["FeedDef"];
export type FeedFile = S["FeedFile"];
export type FeedStatus = S["FeedStatus"];
export type FeedProviderDef = S["FeedProviderDef"];
export type FileSelect = S["FileSelect"];
export type ForwardZoneDef = S["ForwardZoneDef"];
export type IdentityInfo = S["IdentityInfo"];
export type Imported = S["Imported"];
export type Issue = S["Issue"];
export type JobEvent = S["JobEvent"];
export type JobsView = S["JobsView"];
export type ListenerDef = S["ListenerDef"];
export type LookupProviderDef = S["LookupProviderDef"];
export type ModuleInfo = S["ModuleInfo"];
export type Outcome = S["Outcome"];
export type PendingEdge = S["PendingEdge"];
export type PresetView = S["PresetView"];
export type ProfileDef = S["ProfileDef"];
export type ProviderCheckView = S["ProviderCheckView"];
export type ProviderFile = S["ProviderFile"];
export type ProviderStatus = S["ProviderStatus"];
export type ReviewItem = S["ReviewItem"];
export type RunRow = S["RunRow"];
export type ScheduleView = S["ScheduleView"];
export type SecretMeta = S["SecretMeta"];
export type Settings = S["Settings"];
export type SettingsView = S["SettingsView"];
export type UpstreamDef = S["UpstreamDef"];
export type UpstreamGroupDef = S["UpstreamGroupDef"];
export type VersionView = S["VersionView"];
export type WarningView = S["WarningView"];
export type Warninglist = S["Warninglist"];
export type Explanation = S["Explanation"];
export type RequestMade = S["RequestMade"];
export type DryRun = S["DryRun"];
// Wave 5 (core 826b4d6): the query log, attribution, trials, evidence, lookups, DNSSEC, the
// extension builds and the config export.
export type LogRecord = S["LogRecord"];
export type LogDetail = S["LogDetail"];
export type LogReply = S["Reply"];
export type AnswerView = S["AnswerView"];
export type LookupView = S["LookupView"];
export type AttributionView = S["AttributionView"];
export type AttributionMatch = S["Match"];
export type WouldBlockView = S["WouldBlockView"];
export type TopItem = S["TopItem"];
export type SeenDevice = S["Device"];
export type QuerySummary = S["Summary"];
export type TrialResults = S["TrialResults"];
export type EvidenceView = S["EvidenceView"];
export type EvidenceAnswer = S["EvidenceAnswer"];
export type EvidenceRule = S["EvidenceRule"];
export type WireExample = S["WireExample"];
export type LookupModuleInfo = S["LookupModuleInfo"];
export type LookupPresetBuilt = S["LookupPresetBuilt"];
export type LookupProviderStatus = S["LookupProviderStatus"];
export type SelfTestView = S["SelfTestView"];
export type VerdictSetView = S["VerdictSetView"];
export type TempAllowView = S["TempAllowView"];
export type ExtensionBuild = S["ExtensionBuild"];
export type DnssecQueue = S["DnssecQueue"];
export type DnssecResult = S["DnssecResult"];
export type ExportDocument = S["ExportDocument"];
export type RestoreResult = S["RestoreResult"];
// Core 720be97: allow states, typed evidence copies, the LAN CA's view and the UI event frames.
export type AllowView = S["AllowView"];
export type AllowState = S["AllowState"];
export type EvidenceRecord = S["EvidenceRecord"];
export type LancaView = S["LancaView"];
export type PreviousRootView = S["PreviousRootView"];
export type UiEventFrame = S["UiEventFrame"];
export type TempAllowEvent = S["TempAllowEvent"];
export type DnssecEvent = S["DnssecEvent"];
export type RestoreEvent = S["RestoreEvent"];
// Core 07acc1c: the typed `lanca` event naming the previous root, and the `lanca_served` and
// `dnssec_queued` events.
export type LancaEvent = S["LancaEvent"];
export type LancaServedEvent = S["LancaServedEvent"];
export type DnssecQueuedEvent = S["DnssecQueuedEvent"];
// Core a3eb6d5: the coalesced `alert` and `feed_run` events (bounded lists of what changed).
export type AlertEvent = S["AlertEvent"];
export type AlertEventItem = S["AlertEventItem"];
export type FeedRunEvent = S["FeedRunEvent"];
export type FeedRunItem = S["FeedRunItem"];

/** A page of a cursor-paginated list (api.md §7). */
export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

export type Window = "1h" | "6h" | "24h" | "72h";
export const WINDOWS: Window[] = ["1h", "6h", "24h", "72h"];
export const WINDOW_SECONDS: Record<Window, number> = { "1h": 3600, "6h": 21600, "24h": 86400, "72h": 259200 };
