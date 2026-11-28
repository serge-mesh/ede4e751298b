import * as React from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { CheckIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { PageHeader, Section } from "@/components/common/page";
import { DataTable, type DataTableColumn } from "@/components/common/data-table";
import { QueryView } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { CopyField } from "@/components/common/copy-button";
import { Confirm } from "@/components/common/confirm";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useEdgeMutation, useEdges, useIdentity, usePendingEdges } from "@/api/queries";
import { client, unwrap } from "@/api/http";
import { ApiError, errorMessage } from "@/api/errors";
import type { EdgeView, PendingEdge } from "@/api/types";
import { escapeControl } from "@/lib/text";

export function EdgesPage() {
  const edges = useEdges();
  const pending = usePendingEdges();
  const [tab, setTab] = React.useState("edges");
  const pendingCount = pending.data?.length ?? 0;
  return (
    <div>
      <PageHeader
        title="Edges"
        description="Each edge runs from its own config object; requests to an offline edge wait in it and apply when it reconnects."
        actions={
          <Button onClick={() => setTab("add")}>
            <PlusIcon /> Add edge
          </Button>
        }
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="edges">Edges</TabsTrigger>
          <TabsTrigger value="pending">
            Pending approvals {pendingCount > 0 && <Badge variant="warning">{pendingCount}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="add">Add by key</TabsTrigger>
        </TabsList>
        <TabsContent value="edges">
          <QueryView query={edges} rows={5}>
            {(data) => <EdgeTable edges={data} />}
          </QueryView>
        </TabsContent>
        <TabsContent value="pending">
          <QueryView query={pending} rows={3}>
            {(data) => <PendingTable pending={data} />}
          </QueryView>
        </TabsContent>
        <TabsContent value="add">
          <AddEdge onAdded={() => setTab("edges")} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function conditionCount(e: EdgeView): number {
  return Array.isArray(e.status?.conditions) ? (e.status?.conditions as unknown[]).length : 0;
}

function EdgeTable({ edges }: { edges: EdgeView[] }) {
  const navigate = useNavigate();
  const columns = React.useMemo<DataTableColumn<EdgeView>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (e) => e.name || e.id,
        cell: ({ row }) => (
          <Link to="/edges/$edgeId" params={{ edgeId: row.original.id ?? "" }} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
            <SafeText>{row.original.name || row.original.id}</SafeText>
          </Link>
        ),
      },
      { id: "id", header: "Id", accessorFn: (e) => e.id, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "platform", header: "Platform", accessorFn: (e) => e.platform },
      {
        id: "online",
        header: "Status",
        accessorFn: (e) => (e.status?.online ? 1 : 0),
        cell: ({ row }) => (row.original.status?.online ? <Badge variant="success">online</Badge> : <Badge variant="destructive">offline</Badge>),
      },
      {
        id: "conditions",
        header: "Open conditions",
        accessorFn: conditionCount,
        cell: ({ getValue }) => {
          const n = Number(getValue());
          return n ? <Badge variant="warning">{n}</Badge> : <span className="text-muted-foreground">none</span>;
        },
      },
      { id: "last_seen", header: "Last heartbeat", accessorFn: (e) => e.status?.last_seen ?? "", cell: ({ row }) => <TimeAgo value={row.original.status?.last_seen} /> },
      { id: "listeners", header: "Listeners", accessorFn: (e) => e.listeners.length },
      {
        id: "auto_update",
        header: "Auto update",
        accessorFn: (e) => e.auto_update,
        cell: ({ getValue }) => (getValue() ? "on" : <Badge variant="outline">off</Badge>),
      },
    ],
    [],
  );
  return (
    <DataTable
      label="Edges"
      data={edges}
      columns={columns}
      searchable
      searchPlaceholder="Filter edges…"
      onRowClick={(e) => void navigate({ to: "/edges/$edgeId", params: { edgeId: e.id ?? "" } })}
      empty="No edges yet. Add one by key, or approve a pending key."
    />
  );
}

function PendingTable({ pending }: { pending: PendingEdge[] }) {
  const [approving, setApproving] = React.useState<PendingEdge | null>(null);
  const forget = useEdgeMutation((fp: string) => unwrap(client.DELETE("/api/ui/v1/edges/pending/{fp}", { params: { path: { fp } } })));
  const columns = React.useMemo<DataTableColumn<PendingEdge>[]>(
    () => [
      { id: "key", header: "Key fingerprint", accessorFn: (p) => p.key, cell: ({ row }) => <CopyField value={row.original.key} label="Copy fingerprint" /> },
      { id: "claimed", header: "Claimed name", accessorFn: (p) => p.claimed_name ?? "", cell: ({ row }) => <SafeText>{row.original.claimed_name}</SafeText> },
      { id: "addr", header: "Address", accessorFn: (p) => p.addr ?? "", cell: ({ row }) => <SafeText mono>{row.original.addr}</SafeText> },
      { id: "first", header: "First seen", accessorFn: (p) => p.first_seen, cell: ({ row }) => <TimeAgo value={row.original.first_seen} /> },
      { id: "last", header: "Last seen", accessorFn: (p) => p.last_seen, cell: ({ row }) => <TimeAgo value={row.original.last_seen} /> },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex justify-end gap-2">
            <Button size="sm" onClick={() => setApproving(row.original)}>
              <CheckIcon /> Approve
            </Button>
            <Confirm
              title="Forget this key?"
              description="It is listed again if it tries to connect again."
              confirmLabel="Forget"
              onConfirm={() =>
                forget.mutate(row.original.key_path, { onError: (e) => toast.error(errorMessage(e)), onSuccess: () => toast.success("Forgotten") })
              }
            >
              <Button size="sm" variant="ghost" aria-label="Forget key">
                <Trash2Icon />
              </Button>
            </Confirm>
          </div>
        ),
      },
    ],
    [forget],
  );
  return (
    <>
      <p className="mb-3 text-sm text-muted-foreground">
        Unknown keys that tried to connect. Compare each fingerprint with <Mono>picket-edge key</Mono> on the edge before approving it
        (trust on first use).
      </p>
      <DataTable label="Pending keys" data={pending} columns={columns} empty="No unknown keys have tried to connect." />
      {approving && <ApproveDialog pending={approving} onClose={() => setApproving(null)} />}
    </>
  );
}

function ApproveDialog({ pending, onClose }: { pending: PendingEdge; onClose: () => void }) {
  const [name, setName] = React.useState(pending.claimed_name ?? "");
  const [platform, setPlatform] = React.useState<"unifi" | "debian">("unifi");
  const approve = useEdgeMutation(() =>
    unwrap(
      client.POST("/api/ui/v1/edges/pending/{fp}/approve", {
        params: { path: { fp: pending.key_path } },
        body: { name, platform },
      }),
    ),
  );
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Approve edge key</DialogTitle>
          <DialogDescription>
            Stores <Mono>{pending.key}</Mono> as a new edge.
          </DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            approve.mutate(undefined, {
              onSuccess: () => {
                toast.success(`Approved ${escapeControl(name)}`);
                onClose();
              },
              onError: (err) => toast.error(errorMessage(err)),
            });
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="approve-name">Name</Label>
            <Input id="approve-name" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="approve-platform">Platform</Label>
            <Select value={platform} onValueChange={(v) => setPlatform(v as "unifi" | "debian")}>
              <SelectTrigger id="approve-platform">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="unifi">unifi (UCG-Fiber)</SelectItem>
                <SelectItem value="debian">debian</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || approve.isPending}>
              Approve
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

const KEY_RE = /^SHA256:[A-Za-z0-9+/]{43}=?$/;

function AddEdge({ onAdded }: { onAdded: () => void }) {
  const identity = useIdentity();
  const [name, setName] = React.useState("");
  const [key, setKey] = React.useState("");
  const [platform, setPlatform] = React.useState<"unifi" | "debian">("unifi");
  const [error, setError] = React.useState<string | null>(null);
  const add = useEdgeMutation(() => unwrap(client.POST("/api/ui/v1/edges", { body: { name, key: key.trim(), platform } })));
  const keyOk = KEY_RE.test(key.trim());
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title="Add an edge by key" description="Paste the fingerprint that picket-edge key prints on the edge.">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            add.mutate(undefined, {
              onSuccess: () => {
                toast.success(`Added edge ${escapeControl(name)}`);
                setName("");
                setKey("");
                onAdded();
              },
              onError: (err) => setError(err instanceof ApiError ? errorMessage(err) : "Couldn't add the edge."),
            });
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="edge-name">Name</Label>
            <Input id="edge-name" value={name} onChange={(e) => setName(e.target.value)} required placeholder="ucg-fiber" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edge-key">Key fingerprint</Label>
            <Input
              id="edge-key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              required
              placeholder="SHA256:…"
              className="font-mono"
              aria-invalid={(key !== "" && !keyOk) || undefined}
              aria-describedby="edge-key-help"
            />
            <p id="edge-key-help" className="text-xs text-muted-foreground">
              {key !== "" && !keyOk ? "Expected SHA256: followed by 43 base64 characters." : "From picket-edge key on the edge."}
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edge-platform">Platform</Label>
            <Select value={platform} onValueChange={(v) => setPlatform(v as "unifi" | "debian")}>
              <SelectTrigger id="edge-platform">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="unifi">unifi (UCG-Fiber)</SelectItem>
                <SelectItem value="debian">debian</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {escapeControl(error)}
            </p>
          )}
          <Button type="submit" disabled={!name.trim() || !keyOk || add.isPending}>
            <PlusIcon /> Add edge
          </Button>
        </form>
      </Section>
      <Section title="Core's identity" description="On the edge, picket-edge setup shows this fingerprint: compare the two before trusting it.">
        {identity.data ? <CopyField value={identity.data.fingerprint} label="Copy core fingerprint" /> : <span className="text-muted-foreground">…</span>}
      </Section>
    </div>
  );
}
