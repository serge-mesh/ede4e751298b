import * as React from "react";
import { toast } from "sonner";
import { Loader2Icon, SaveIcon, Trash2Icon, TriangleAlertIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { SchemaForm, type FieldOverride } from "@/components/schema-form/schema-form";
import { Confirm } from "./confirm";
import { useDraft, useHeldText } from "./drafts";
import { ErrorState, LoadingState, RefetchError } from "./states";
import { ENTITY_LABEL, ENTITY_SCHEMA, entityId, type EntityKind, type EntityTypes, type SaveFlags } from "@/api/entities";
import { StaleEntity, useDeleteEntity, useEntity, useSaveEntity } from "@/api/queries";
import { ApiError, errorMessage } from "@/api/errors";
import type { Issue, Outcome } from "@/api/types";
import { openapiRoot } from "@/lib/openapi";
import { clone, defaultValue, deref, validate, type FieldErrors } from "@/lib/schema";
import { escapeControl } from "@/lib/text";
import { COUPLED_FIELDS, deepEqual, mergeKeepingMine } from "@/lib/merge";
import { idFromName } from "@/lib/ids";
import { idRule } from "./id-field";

export function IssueList({ issues, title }: { issues: Issue[]; title: string }) {
  if (issues.length === 0) return null;
  const errors = issues.some((i) => i.severity === "error");
  return (
    <Alert variant={errors ? "destructive" : "warning"}>
      <TriangleAlertIcon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        <ul className="list-disc space-y-0.5 pl-4">
          {issues.map((i, n) => (
            <li key={n}>
              {escapeControl(i.message)}
              {i.field && <code className="ml-1 font-mono text-xs">({i.field})</code>}
            </li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  );
}

export interface EntityFormProps<K extends EntityKind> {
  kind: K;
  /** The entity to edit; omitted to create one. */
  id?: string;
  /** The starting value for a new entity (a preset or a duplicate). */
  initial?: Partial<EntityTypes[K]>;
  overrides?: Record<string, FieldOverride>;
  hidden?: string[];
  readOnly?: string[];
  labels?: Record<string, string>;
  order?: string[];
  onSaved?: (o: Outcome, value: EntityTypes[K]) => void;
  onDeleted?: () => void;
  onCancel?: () => void;
  /** Extra controls next to Save (e.g. "Clear cached verdicts on save"). */
  extraActions?: React.ReactNode;
  saveFlags?: SaveFlags;
  /** Called before saving; may adjust the value or refuse (return null). */
  beforeSave?: (v: EntityTypes[K]) => EntityTypes[K] | null;
  /** Rendered above the form, with the current value. */
  header?: (v: EntityTypes[K], set: (v: EntityTypes[K]) => void) => React.ReactNode;
  /** Rendered below the form, with the current value and the saved one it was edited from. */
  footer?: (v: EntityTypes[K], saved: EntityTypes[K] | undefined) => React.ReactNode;
  /** Asks before saving when it returns something (e.g. an edit that closes a feed's entries). */
  confirmSave?: (v: EntityTypes[K], saved: EntityTypes[K] | undefined) => { title: string; description: React.ReactNode; confirmLabel?: string } | null;
  /** Handles a 409 conflict (e.g. a feed provider edit that would delete feeds). */
  onConflict?: (e: ApiError, retry: (flags: SaveFlags) => void) => void;
  deleteDescription?: React.ReactNode;
  canDelete?: boolean;
}

/** Loads (when editing) and renders an entity form from the OpenAPI schema. */
export function EntityForm<K extends EntityKind>(props: EntityFormProps<K>) {
  const q = useEntity(props.kind, props.id);
  if (props.id) {
    if (!q.data) return q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <LoadingState rows={6} />;
    // A failed refetch keeps the form, and its draft, mounted (core.md §12).
    return (
      <div className="space-y-4">
        {q.error && <RefetchError error={q.error} onRetry={() => void q.refetch()} />}
        <EntityFormInner key={`${props.id}`} {...props} loaded={q.data} />
      </div>
    );
  }
  return <EntityFormInner {...props} loaded={undefined} />;
}

function EntityFormInner<K extends EntityKind>({
  kind,
  id,
  initial,
  overrides,
  hidden,
  readOnly,
  labels,
  order,
  onSaved,
  onDeleted,
  onCancel,
  extraActions,
  saveFlags,
  beforeSave,
  header,
  footer,
  confirmSave,
  onConflict,
  deleteDescription,
  canDelete = true,
  loaded,
}: EntityFormProps<K> & { loaded: EntityTypes[K] | undefined }) {
  const schemaName = ENTITY_SCHEMA[kind];
  const schema = React.useMemo(() => ({ $ref: `#/components/schemas/${schemaName}` }), [schemaName]);
  // Only the first value starts the form; later data is compared with its base below.
  const [start] = React.useState<EntityTypes[K]>(() => {
    if (loaded) return clone(loaded);
    const d = (defaultValue(schema, openapiRoot) ?? {}) as Record<string, unknown>;
    return { ...d, ...(clone(initial) ?? {}) } as EntityTypes[K];
  });
  // Entities have no server-side version check (api.md §7): the form keeps the saved value its
  // draft was edited from (`base`). New data for a clean form replaces both; for a dirty form it
  // waits in `incoming` until the admin reloads or keeps their changes on top of it, so a save
  // never sends values older than what the form has seen.
  const [base, setBase] = React.useState<EntityTypes[K]>(start);
  const [value, setValue] = React.useState<EntityTypes[K]>(start);
  const [incoming, setIncoming] = React.useState<EntityTypes[K] | null>(null);
  const [seen, setSeen] = React.useState(loaded);
  // Text a control holds that isn't in `value` yet (unparsed JSON, a tag typed but not added) is a
  // draft too, though there's nothing new to save.
  const text = useHeldText();
  const changed = !deepEqual(value, base);
  const dirty = changed || text.held;
  // Kept by its tab, asked about by its sheet (components/common/drafts.tsx).
  useDraft(dirty);
  if (loaded !== seen) {
    setSeen(loaded);
    if (loaded && !deepEqual(loaded, base)) {
      if (dirty) setIncoming(clone(loaded));
      else {
        setBase(clone(loaded));
        setValue(clone(loaded));
        setIncoming(null);
      }
    } else setIncoming(null);
  }
  const [errors, setErrors] = React.useState<FieldErrors>({});
  const [issues, setIssues] = React.useState<Issue[]>([]);
  const [warnings, setWarnings] = React.useState<Issue[]>([]);
  const [asking, setAsking] = React.useState<{ title: string; description: React.ReactNode; confirmLabel?: string } | null>(null);
  // Creating: the id follows the name (feeds.md §1's rule; profiles a DNS label, core.md §2)
  // until the admin types one, so it shows before saving; core derives none. A cleared id counts
  // as not typed: it follows the name again (shown as the field's placeholder until then).
  const idFromNameKind = React.useMemo(() => {
    if (id) return false;
    const props = deref(schema, openapiRoot).properties ?? {};
    return "id" in props && "name" in props;
  }, [id, schema]);
  const [idTyped, setIdTyped] = React.useState(() => !!(start as { id?: string }).id);
  const nameNow = (value as { name?: string }).name ?? "";
  const idPlaceholder = React.useMemo(() => (idFromNameKind && !idTyped ? { id: idFromName(kind, nameNow) } : undefined), [idFromNameKind, idTyped, kind, nameNow]);
  const save = useSaveEntity(kind);
  const del = useDeleteEntity(kind);
  const system = (value as { system?: boolean }).system === true;
  const label = ENTITY_LABEL[kind];
  const saved = id ? base : undefined;

  const onChange = (next: EntityTypes[K]) => {
    if (!idFromNameKind) {
      setValue(next);
      return;
    }
    const prev = value as { id?: string; name?: string };
    const n = next as { id?: string; name?: string };
    if ((n.id ?? "") !== (prev.id ?? "")) {
      setIdTyped((n.id ?? "") !== "");
      setValue(next);
    } else if (!idTyped && (n.name ?? "") !== (prev.name ?? "")) setValue({ ...next, id: idFromName(kind, n.name ?? "") } as EntityTypes[K]);
    else setValue(next);
  };

  const doSave = (flags: SaveFlags = {}) => {
    let body = clone(value);
    if (beforeSave) {
      const b = beforeSave(body);
      if (!b) return;
      body = b;
    }
    // A cleared id follows the name (the placeholder shows it).
    if (idFromNameKind && !idTyped && !(body as { id?: string }).id) body = { ...body, id: idFromName(kind, (body as { name?: string }).name ?? "") };
    const local = validate(schema, body, openapiRoot);
    // Core derives no id and refuses an empty one (422); it checks the rest of the rule itself.
    if (idFromNameKind && !(body as { id?: string }).id) local.id = `Give it an id, or a name to take it from. ${idRule(kind)}`;
    setErrors(local);
    if (Object.keys(local).length > 0) {
      toast.error("Fix the highlighted fields first.");
      return;
    }
    setIssues([]);
    // An edit is sent only while the entity is still the form's base, in the entity's write
    // queue (api/queries.ts): a change saved since (another tab, an action on this page) comes
    // back as StaleEntity and shows as "changed elsewhere" instead of being overwritten.
    save.mutate(
      { id, body, base: id ? base : undefined, flags: { ...saveFlags, ...flags } },
      {
        onSuccess: (o) => {
          setWarnings(o.warnings ?? []);
          toast.success(id ? `Saved ${label} ${escapeControl(o.id)}` : `Created ${label} ${escapeControl(o.id)}`);
          if (o.feeds_added?.length) toast.info(`Feeds added: ${o.feeds_added.map(escapeControl).join(", ")}`);
          if (o.feeds_deleted?.length) toast.info(`Feeds deleted: ${o.feeds_deleted.map(escapeControl).join(", ")}`);
          const stored = (o.entity as EntityTypes[K]) ?? body;
          if (id) {
            setBase(clone(stored));
            setValue(clone(stored));
            setIncoming(null);
          }
          onSaved?.(o, stored);
        },
        onError: (e) => {
          if (e instanceof StaleEntity) {
            setIncoming(clone(e.current as EntityTypes[K]));
            toast.error(`This ${label} changed since you started editing: reload it or keep your changes, then save.`);
            return;
          }
          if (e instanceof ApiError) {
            if (e.status === 409 && onConflict) {
              onConflict(e, (f) => doSave(f));
              return;
            }
            setErrors(e.fieldErrors());
            setIssues(e.issues.filter((i) => !i.field || i.severity !== "error"));
          }
          toast.error(errorMessage(e));
        },
      },
    );
  };

  const submit = () => {
    const ask = confirmSave?.(value, saved);
    if (ask) setAsking(ask);
    else doSave();
  };

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
      aria-label={id ? `Edit ${label}` : `New ${label}`}
    >
      {incoming && (
        <Alert variant="warning">
          <TriangleAlertIcon />
          <AlertTitle>This {label} changed elsewhere</AlertTitle>
          <AlertDescription>
            <p>It was saved since you started editing (another tab, another admin, or an action on this page). Reload it, or keep your changes on top of the new values.</p>
            <span className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setBase(incoming);
                  setValue(clone(incoming));
                  setIncoming(null);
                  text.reset();
                }}
              >
                Reload
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  const { value: merged, replaced } = mergeKeepingMine(base, value, incoming, COUPLED_FIELDS[kind]);
                  setValue(merged);
                  setBase(incoming);
                  setIncoming(null);
                  // core.md §2 checks these fields together, so they were kept as one value.
                  for (const g of replaced) toast.info(`Kept your ${g.join(", ")} as you edited them: core checks them together, so the change made elsewhere to them is replaced.`);
                }}
              >
                Keep my changes
              </Button>
            </span>
          </AlertDescription>
        </Alert>
      )}
      {text.scope(
        <>
          {header?.(value, onChange)}
          <IssueList issues={issues} title="Core refused the change" />
          <SchemaForm
            schema={schema}
            root={openapiRoot}
            value={value}
            onChange={(v) => onChange(v as EntityTypes[K])}
            errors={errors}
            overrides={overrides}
            hidden={[...(hidden ?? []), "system"]}
            readOnly={[...(readOnly ?? []), ...(id ? ["id"] : [])]}
            labels={labels}
            placeholders={idPlaceholder}
            order={order}
            mode={id ? "edit" : "create"}
            disabled={save.isPending}
          />
          {footer?.(value, saved)}
        </>,
      )}
      <IssueList issues={warnings} title="Saved, with warnings" />
      <div className="sticky bottom-0 z-10 -mx-1 flex flex-wrap items-center gap-2 border-t bg-background/95 px-1 py-3 backdrop-blur">
        <Button type="submit" disabled={save.isPending || (!!id && !changed) || !!incoming} title={incoming ? "Reload or keep your changes first." : undefined}>
          {save.isPending ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
          {id ? "Save" : `Create ${label}`}
        </Button>
        {id && dirty && (
          <Button
            variant="ghost"
            onClick={() => {
              setValue(clone(base));
              text.reset();
            }}
            disabled={save.isPending}
          >
            Discard changes
          </Button>
        )}
        {onCancel && (
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
        )}
        {extraActions}
        {id && canDelete && !system && (
          <Confirm
            title={`Delete ${label} ${escapeControl(entityId(kind, value) || id)}?`}
            description={deleteDescription ?? "This can't be undone."}
            confirmLabel="Delete"
            destructive
            onConfirm={() =>
              del.mutate(id, {
                onSuccess: (o) => {
                  toast.success(`Deleted ${label} ${escapeControl(id)}`);
                  if (o?.warnings?.length) setWarnings(o.warnings);
                  onDeleted?.();
                },
                onError: (e) => toast.error(errorMessage(e)),
              })
            }
          >
            <Button variant="outline" className="ml-auto text-destructive" disabled={del.isPending}>
              <Trash2Icon /> Delete
            </Button>
          </Confirm>
        )}
        {id && system && <span className="ml-auto text-xs text-muted-foreground">System {label}: can be edited, not deleted.</span>}
      </div>
      <AlertDialog open={!!asking} onOpenChange={(o) => !o && setAsking(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{asking?.title}</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>{asking?.description}</div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              destructive
              onClick={() => {
                setAsking(null);
                doSave();
              }}
            >
              {asking?.confirmLabel ?? "Save"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </form>
  );
}
