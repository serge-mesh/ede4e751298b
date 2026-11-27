import * as React from "react";
import { EditorState, Text } from "@codemirror/state";
import {
  EditorView,
  drawSelection,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  keymap,
  lineNumbers,
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";

const theme = EditorView.theme({
  "&": { fontSize: "12.5px", backgroundColor: "var(--background)", color: "var(--foreground)" },
  ".cm-content": { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", caretColor: "var(--foreground)" },
  ".cm-gutters": { backgroundColor: "var(--muted)", color: "var(--muted-foreground)", borderRight: "1px solid var(--border)" },
  ".cm-activeLine": { backgroundColor: "color-mix(in oklab, var(--accent) 60%, transparent)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--accent)" },
  "&.cm-focused": { outline: "2px solid color-mix(in oklab, var(--ring) 50%, transparent)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "color-mix(in oklab, var(--primary) 30%, transparent) !important" },
  ".cm-specialChar": { color: "var(--destructive)" },
});

/** What the page does with the editor; the document lives in CodeMirror, never in React state. */
export interface CodeEditorHandle {
  /** The document now: a CodeMirror `Text` (a rope), turned into a string only when saved. */
  doc(): Text;
  /** Replaces the document (a reload) and makes it the clean one. */
  load(text: string): void;
  /** Makes `doc` (one this editor held, e.g. the one a save sent) the clean document. */
  markClean(doc: Text): void;
  /** Puts the clean document back (Discard). */
  revert(): void;
}

/**
 * A virtualised text editor (CodeMirror 6) for a manual feed's file (core.md §12). It renders
 * only the visible lines, and does no whole-document work per keystroke: dirtiness compares the
 * document with the clean one through `Text.eq`, which skips the subtrees an edit left shared, so
 * a file at the download cap stays responsive. Text is never parsed as HTML; control characters
 * show as placeholders (highlightSpecialChars).
 */
export function CodeEditor({
  ref,
  initial,
  onDirtyChange,
  readOnly,
  height = "60vh",
  ariaLabel,
}: {
  ref?: React.Ref<CodeEditorHandle>;
  /** The starting document, read once when the editor is created. */
  initial: string;
  /** Called when the document starts or stops differing from the clean one. */
  onDirtyChange?: (dirty: boolean) => void;
  readOnly?: boolean;
  height?: string;
  ariaLabel: string;
}) {
  const host = React.useRef<HTMLDivElement>(null);
  const view = React.useRef<EditorView | null>(null);
  const clean = React.useRef<Text>(Text.of([""]));
  const dirty = React.useRef(false);
  const initialRef = React.useRef(initial);
  const onDirtyRef = React.useRef(onDirtyChange);
  React.useEffect(() => {
    onDirtyRef.current = onDirtyChange;
  });

  const check = React.useCallback((doc: Text) => {
    const d = !doc.eq(clean.current);
    if (d !== dirty.current) {
      dirty.current = d;
      onDirtyRef.current?.(d);
    }
  }, []);

  React.useEffect(() => {
    if (!host.current) return;
    const state = EditorState.create({
      doc: view.current?.state.doc ?? initialRef.current,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightSpecialChars(),
        history(),
        drawSelection(),
        highlightActiveLine(),
        keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
        EditorState.readOnly.of(!!readOnly),
        EditorView.editable.of(!readOnly),
        EditorView.contentAttributes.of({ "aria-label": ariaLabel, spellcheck: "false" }),
        EditorView.updateListener.of((u) => {
          if (u.docChanged) check(u.state.doc);
        }),
        theme,
      ],
    });
    if (!view.current) clean.current = state.doc;
    const v = new EditorView({ parent: host.current, state });
    view.current = v;
    return () => {
      v.destroy();
    };
  }, [readOnly, ariaLabel, check]);

  React.useImperativeHandle(
    ref,
    () => ({
      doc: () => view.current?.state.doc ?? clean.current,
      load: (text: string) => {
        const v = view.current;
        if (!v) return;
        v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: text } });
        clean.current = v.state.doc;
        check(v.state.doc);
      },
      markClean: (doc: Text) => {
        clean.current = doc;
        check(view.current?.state.doc ?? doc);
      },
      revert: () => {
        const v = view.current;
        if (!v) return;
        v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: clean.current } });
      },
    }),
    [check],
  );

  return <div ref={host} className="overflow-hidden rounded-md border" style={{ height }} data-testid="code-editor" />;
}
