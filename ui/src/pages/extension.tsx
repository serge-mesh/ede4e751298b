import { DownloadIcon } from "lucide-react";
import { PageHeader, Section } from "@/components/common/page";
import { QueryView } from "@/components/common/states";
import { CopyField } from "@/components/common/copy-button";
import { Mono, SafeText } from "@/components/common/text";
import { Button } from "@/components/ui/button";
import { useQuery } from "@tanstack/react-query";
import { client, unwrap } from "@/api/http";
import { formatBytes } from "@/lib/format";

/**
 * Only core's own extension downloads are linked: `/extension/<file>` for the build's own file
 * (web/extension.rs serves only listed builds there, open without basic auth).
 */
export function safePath(p: string, file: string): string | null {
  return p === `/extension/${file}` && /^[A-Za-z0-9._+-]+$/.test(file) && !file.includes("..") ? p : null;
}

const STEPS: Record<string, string[]> = {
  brave: [
    "Download the Brave build and unpack it into a folder that stays put.",
    "Open brave://extensions and turn on Developer mode.",
    "Choose Load unpacked and pick the folder.",
    "Open the extension's options and enter the bypass API address of a DoH listener with the bypass API on.",
  ],
  // browser-extension.md §1: the build is unsigned (Mozilla's signing would send every build to
  // Mozilla), so it installs only where signature checks can be turned off.
  firefox: [
    "Use Firefox Developer Edition, Nightly or ESR: release Firefox only installs signed add-ons, and this build is unsigned.",
    "Open about:config and set xpinstall.signatures.required to false.",
    "Download the Firefox build (an unsigned .xpi) and check its SHA-256.",
    "Open about:addons, choose the gear menu, then Install Add-on From File…, and pick the file.",
    "Open the extension's options and enter the bypass API address of a DoH listener with the bypass API on.",
  ],
};

/** The accepted risk of the Firefox steps (security.md §5). */
const FIREFOX_RISK =
  "Turning xpinstall.signatures.required off disables signature checks for every add-on in that Firefox profile, and the SHA-256 shown here comes from core, so it doesn't protect against a compromised core. The extension is optional.";

/** Browser extension: the Brave and Firefox builds, with SHA-256 sums and install steps. */
export function ExtensionPage() {
  const builds = useQuery({ queryKey: ["extension"], queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/extension", { signal })), staleTime: Infinity });
  return (
    <div className="space-y-4">
      <PageHeader
        title="Browser extension"
        description="A block page and temporary allows in Brave and Firefox, served by the edge's bypass API. Check a download's SHA-256 before installing it."
      />
      <QueryView query={builds} what="Extension builds" rows={3} empty={<p className="text-sm text-muted-foreground">No builds in this core package.</p>} isEmpty={(d) => d.items.length === 0}>
        {(d) => (
          <div className="grid gap-4 lg:grid-cols-2">
            {d.items.map((b) => {
              const href = safePath(b.path, b.file);
              return (
                <Section key={b.path} title={<span className="capitalize">{b.browser}</span>} description={`Version ${b.version}, ${formatBytes(b.size)}`}>
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <SafeText mono>{b.file}</SafeText>
                      {href && (
                        <Button asChild size="sm" variant="outline">
                          <a href={href} download>
                            <DownloadIcon /> Download
                          </a>
                        </Button>
                      )}
                    </div>
                    <div className="text-sm">
                      SHA-256 <CopyField value={b.sha256} label="Copy the SHA-256" />
                    </div>
                  </div>
                </Section>
              );
            })}
          </div>
        )}
      </QueryView>
      <div className="grid gap-4 lg:grid-cols-2">
        {Object.entries(STEPS).map(([browser, steps]) => (
          <Section key={browser} title={<span>Install in <span className="capitalize">{browser}</span></span>}>
            <ol className="list-decimal space-y-1 pl-5 text-sm">
              {steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
            {browser === "firefox" && <p className="mt-2 text-xs text-muted-foreground">Accepted risk: {FIREFOX_RISK}</p>}
          </Section>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        Verify a download with <Mono>sha256sum</Mono> (Linux) or <Mono>shasum -a 256</Mono> (macOS) and compare it with the sum shown here.
      </p>
    </div>
  );
}
