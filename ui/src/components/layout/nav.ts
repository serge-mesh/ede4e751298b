import {
  BellIcon,
  BoxesIcon,
  CableIcon,
  CpuIcon,
  DownloadCloudIcon,
  FileTextIcon,
  GaugeIcon,
  KeyRoundIcon,
  NetworkIcon,
  PuzzleIcon,
  RadarIcon,
  RouterIcon,
  ScrollTextIcon,
  SettingsIcon,
  ShieldCheckIcon,
  TimerIcon,
  TriangleAlertIcon,
  UsersIcon,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

export const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: GaugeIcon },
      { to: "/query-log", label: "Query log", icon: ScrollTextIcon },
      { to: "/alerts", label: "Alerts", icon: BellIcon },
    ],
  },
  {
    group: "Network",
    items: [
      { to: "/edges", label: "Edges", icon: RouterIcon },
      { to: "/listeners", label: "Listeners", icon: CableIcon },
      { to: "/clients", label: "Clients", icon: UsersIcon },
      { to: "/profiles", label: "Profiles", icon: ShieldCheckIcon },
      { to: "/upstreams", label: "Upstreams and zones", icon: NetworkIcon },
      { to: "/temporary-allows", label: "Temporary allows", icon: TimerIcon },
    ],
  },
  {
    group: "Filtering",
    items: [
      { to: "/feed-providers", label: "Feed providers", icon: DownloadCloudIcon },
      { to: "/feeds", label: "Feeds", icon: FileTextIcon },
      { to: "/bundles", label: "Bundles", icon: BoxesIcon },
      { to: "/warninglists", label: "Warninglists", icon: TriangleAlertIcon },
      { to: "/lookup-providers", label: "Lookup providers", icon: RadarIcon },
    ],
  },
  {
    group: "Core",
    items: [
      { to: "/dnssec", label: "DNSSEC", icon: KeyRoundIcon },
      { to: "/system", label: "System", icon: CpuIcon },
      { to: "/extension", label: "Browser extension", icon: PuzzleIcon },
      { to: "/settings", label: "Settings", icon: SettingsIcon },
    ],
  },
];
