import * as React from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { CopyPlusIcon, PencilIcon, PlusIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { DataTable } from "./data-table";
import { QueryView } from "./states";
import { EntityForm, type EntityFormProps } from "./entity-editor";
import { DraftScope, useDiscardGuard } from "./drafts";
import { useEntities } from "@/api/queries";
import { ENTITY_LABEL, entityId, type EntityKind, type EntityTypes } from "@/api/entities";
import { escapeControl } from "@/lib/text";
import { clone } from "@/lib/schema";

type FormExtras<K extends EntityKind> = Omit<EntityFormProps<K>, "kind" | "id" | "initial" | "onSaved" | "onDeleted" | "onCancel">;

/**
 * A list of one entity kind with create, edit and duplicate in a side sheet (core.md §2: no
 * inheritance; the UI offers "duplicate").
 */
export function EntityList<K extends EntityKind>({
  kind,
  columns,
  form,
  description,
  empty,
  newLabel,
  duplicate = true,
  onOpen,
}: {
  kind: K;
  columns: ColumnDef<EntityTypes[K], unknown>[];
  form?: FormExtras<K>;
  description?: React.ReactNode;
  empty?: React.ReactNode;
  newLabel?: string;
  duplicate?: boolean;
  /** Navigate to a detail page instead of opening the sheet. */
  onOpen?: (e: EntityTypes[K]) => void;
}) {
  const q = useEntities(kind);
  const [editing, setEditing] = React.useState<{ id?: string; initial?: Partial<EntityTypes[K]> } | null>(null);
  // Escape, a click outside or the close button ask first while the form holds unsaved changes.
  const guard = useDiscardGuard(() => setEditing(null));
  const label = ENTITY_LABEL[kind];
  const cols = React.useMemo<ColumnDef<EntityTypes[K], unknown>[]>(
    () => [
      ...columns,
      {
        id: "_actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            {(row.original as { system?: boolean }).system && <Badge variant="outline">system</Badge>}
            <Button variant="ghost" size="icon-sm" aria-label={`Edit ${entityId(kind, row.original)}`} onClick={() => (onOpen ? onOpen(row.original) : setEditing({ id: entityId(kind, row.original) }))}>
              <PencilIcon />
            </Button>
            {duplicate && (
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`Duplicate ${entityId(kind, row.original)}`}
                onClick={() => {
                  const copy = clone(row.original) as Record<string, unknown>;
                  delete copy.system;
                  const base = entityId(kind, row.original);
                  if (kind === "clients") copy.name = `${base}-copy`;
                  else {
                    copy.id = `${base}-copy`;
                    if (typeof copy.name === "string") copy.name = `${copy.name} (copy)`;
                  }
                  setEditing({ initial: copy as Partial<EntityTypes[K]> });
                }}
              >
                <CopyPlusIcon />
              </Button>
            )}
          </div>
        ),
      },
    ],
    [columns, kind, duplicate, onOpen],
  );
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {description ? <div className="text-sm text-muted-foreground">{description}</div> : <span />}
        <Button onClick={() => setEditing({})}>
          <PlusIcon /> {newLabel ?? `New ${label}`}
        </Button>
      </div>
      <QueryView query={q} rows={5}>
        {(data) => (
          <DataTable
            label={label}
            data={data}
            columns={cols}
            searchable
            searchPlaceholder={`Filter ${label}s…`}
            empty={empty}
            getRowId={(e) => entityId(kind, e)}
            onRowClick={(e) => (onOpen ? onOpen(e) : setEditing({ id: entityId(kind, e) }))}
          />
        )}
      </QueryView>
      <Sheet open={!!editing} onOpenChange={(o) => !o && guard.requestClose()}>
        <SheetContent className="sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle>{editing?.id ? `Edit ${label} ${escapeControl(editing.id)}` : `New ${label}`}</SheetTitle>
            <SheetDescription>Fields come from core's schema; hover the info icons for what each does.</SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing && (
              <DraftScope onDirty={guard.onDirty}>
                <EntityForm<K>
                  key={editing.id ?? "new"}
                  kind={kind}
                  id={editing.id}
                  initial={editing.initial}
                  {...form}
                  onSaved={(o) => setEditing(editing.id ? { id: o.id } : null)}
                  onDeleted={() => setEditing(null)}
                  onCancel={() => setEditing(null)}
                />
              </DraftScope>
            )}
          </div>
        </SheetContent>
      </Sheet>
      {guard.dialog}
    </div>
  );
}
