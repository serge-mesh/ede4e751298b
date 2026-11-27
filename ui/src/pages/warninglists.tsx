import { Link } from "@tanstack/react-router";
import { PageHeader, Section } from "@/components/common/page";
import { QueryView } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { Badge } from "@/components/ui/badge";
import { useWarninglists } from "@/api/queries";
import type { Warninglist } from "@/api/types";
import { WarningPages, useBundleWarnings } from "./bundle-detail";

/** Warn bundles (warn-common first), the feeds whose warn_on names each, and the warnings found. */
export function WarninglistsPage() {
  const q = useWarninglists();
  return (
    <div className="space-y-4">
      <PageHeader
        title="Warninglists"
        description="Feeds of known-good identifiers in warn bundles. When a block bundle compiles, an entry that matches a warn bundle its feed's warn_on names records a warning. Warninglists never allow or block, and never reach an edge."
      />
      <QueryView query={q} rows={5} empty={<p className="text-sm text-muted-foreground">No warn bundles.</p>} isEmpty={(d) => d.length === 0}>
        {(list) => (
          <div className="space-y-4">
            {[...list]
              .sort((a, b) => (a.bundle === "warn-common" ? -1 : b.bundle === "warn-common" ? 1 : a.bundle.localeCompare(b.bundle)))
              .map((w) => (
                <WarnBundle key={w.bundle} w={w} />
              ))}
          </div>
        )}
      </QueryView>
    </div>
  );
}

function WarnBundle({ w }: { w: Warninglist }) {
  const warnings = useBundleWarnings(w.bundle);
  return (
    <Section
      title={
        <span className="flex flex-wrap items-center gap-2">
          <Link to="/bundles/$bundleId" params={{ bundleId: w.bundle }} className="hover:underline">
            <Mono>{w.bundle}</Mono>
          </Link>
          {w.name && w.name !== w.bundle && (
            <span className="font-normal text-muted-foreground">
              <SafeText>{w.name}</SafeText>
            </span>
          )}
          {w.open_warnings > 0 && <Badge variant="warning">{w.open_warnings} open warnings</Badge>}
        </span>
      }
    >
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <h4 className="mb-1 text-sm font-medium">Its warninglists (member feeds)</h4>
          {w.feeds.length === 0 ? (
            <p className="text-sm text-muted-foreground">None.</p>
          ) : (
            <ul className="flex flex-wrap gap-1.5">
              {w.feeds.map((f) => (
                <li key={f}>
                  <Link to="/feeds/$feedId" params={{ feedId: f }}>
                    <Badge variant="secondary">
                      <SafeText>{f}</SafeText>
                    </Badge>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h4 className="mb-1 text-sm font-medium">Feeds checked against it (warn_on)</h4>
          {w.checked_feeds.length === 0 ? (
            <p className="text-sm text-muted-foreground">No feed's warn_on names it, so it is never checked.</p>
          ) : (
            <ul className="flex flex-wrap gap-1.5">
              {w.checked_feeds.map((f) => (
                <li key={f}>
                  <Link to="/feeds/$feedId" params={{ feedId: f }}>
                    <Badge variant="outline">
                      <SafeText>{f}</SafeText>
                    </Badge>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <div className="mt-4">
        <h4 className="mb-1 text-sm font-medium">Warnings found</h4>
        <QueryView query={warnings} rows={3}>
          {() => <WarningPages q={warnings} />}
        </QueryView>
      </div>
    </Section>
  );
}
