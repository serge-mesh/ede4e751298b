// Unsaved drafts: a form, or a control holding text not yet in its form's value, says whether it
// holds one (`useDraft`), and what encloses it keeps it or asks before dropping it: a tab stays mounted, out of sight, while another shows (ui/tabs.tsx), and
// a sheet asks before it closes (`useDiscardGuard`).
import * as React from "react";
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

type Report = (key: string, dirty: boolean) => void;
const DraftContext = React.createContext<Report | null>(null);

/** Tells the enclosing `DraftScope` whether this form holds unsaved changes (until it unmounts). */
export function useDraft(dirty: boolean) {
  const report = React.useContext(DraftContext);
  const key = React.useId();
  React.useEffect(() => {
    if (!report || !dirty) return;
    report(key, true);
    return () => report(key, false);
  }, [report, key, dirty]);
}

/** Collects the drafts of the forms inside it (`useDraft`, the nearest scope only): `onDirty` hears whether any holds one. */
export function DraftScope({ onDirty, children }: { onDirty: (dirty: boolean) => void; children: React.ReactNode }) {
  const drafts = React.useRef(new Set<string>());
  const notify = React.useRef(onDirty);
  React.useEffect(() => {
    notify.current = onDirty;
  });
  const report = React.useCallback<Report>((key, dirty) => {
    const had = drafts.current.size > 0;
    if (dirty) drafts.current.add(key);
    else drafts.current.delete(key);
    if (had !== drafts.current.size > 0) notify.current(!had);
  }, []);
  return <DraftContext.Provider value={report}>{children}</DraftContext.Provider>;
}

/**
 * For a form that compares its value with a base: text its controls hold that isn't in the value
 * yet (unparsed JSON, a tag or map key typed but not added: their `useDraft`) is a draft too. The
 * controls go inside `scope(…)`; `held` says whether any holds such text; `reset` drops it by
 * remounting them (Discard changes, Reload).
 */
export function useHeldText() {
  const [held, setHeld] = React.useState(false);
  const [epoch, setEpoch] = React.useState(0);
  const scope = (children: React.ReactNode) => (
    <DraftScope key={epoch} onDirty={setHeld}>
      {children}
    </DraftScope>
  );
  return { held, reset: () => setEpoch((e) => e + 1), scope };
}

/**
 * For a sheet whose forms may hold a draft: `requestClose` (its Escape, outside click or close
 * button) closes it at once while none does, else asks first (`dialog`, rendered beside the sheet).
 * The forms go inside `<DraftScope onDirty={onDirty}>`.
 */
export function useDiscardGuard(close: () => void) {
  const [dirty, setDirty] = React.useState(false);
  const [asking, setAsking] = React.useState(false);
  const requestClose = () => (dirty ? setAsking(true) : close());
  const dialog = (
    <AlertDialog open={asking} onOpenChange={setAsking}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Discard your changes?</AlertDialogTitle>
          <AlertDialogDescription>They aren't saved yet.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Keep editing</AlertDialogCancel>
          <AlertDialogAction
            destructive
            onClick={() => {
              setAsking(false);
              close();
            }}
          >
            Discard
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
  return { onDirty: setDirty, requestClose, dialog };
}
