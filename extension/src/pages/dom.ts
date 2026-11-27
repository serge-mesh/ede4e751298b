// DOM helpers for the extension's pages. Text from outside the extension (names, EXTRA-TEXT
// values, edge messages) is only ever set as text (`textContent`), never as HTML
// (browser-extension.md §4), and control characters are shown escaped.

import { printable } from '../shared/host';

type Child = Node | string | null | undefined | false;

export interface Props {
  class?: string;
  text?: string;
  title?: string;
  attrs?: Record<string, string>;
  hidden?: boolean;
}

/** An element with text and children; strings become text nodes. */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props.class !== undefined) {
    el.className = props.class;
  }
  if (props.title !== undefined) {
    el.title = printable(props.title);
  }
  if (props.hidden === true) {
    el.hidden = true;
  }
  for (const [k, v] of Object.entries(props.attrs ?? {})) {
    el.setAttribute(k, v);
  }
  if (props.text !== undefined) {
    el.textContent = printable(props.text);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) {
      continue;
    }
    el.append(typeof c === 'string' ? document.createTextNode(printable(c)) : c);
  }
  return el;
}

/** Sets an element's text (escaped control characters, never HTML). */
export function setText(el: Element, text: string): void {
  el.textContent = printable(text);
}

/** An element of a given type the page's HTML must hold. */
export function byId<T extends HTMLElement>(id: string, type: { prototype: T; new (): T }): T {
  const el = document.getElementById(id);
  if (!(el instanceof type)) {
    throw new Error(`missing #${id}`);
  }
  return el;
}

/** "14:05" (or a date and time when it isn't today). */
export function clockTime(unixS: number, nowMs: number = Date.now()): string {
  const d = new Date(unixS * 1000);
  const today = new Date(nowMs);
  const sameDay = d.toDateString() === today.toDateString();
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  return sameDay ? time : `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
}

/** "45 s", "12 min", "3 h 5 min". */
export function span(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) {
    return `${String(s)} s`;
  }
  const m = Math.round(s / 60);
  if (m < 60) {
    return `${String(m)} min`;
  }
  const hours = Math.floor(m / 60);
  const rest = m % 60;
  return rest === 0 ? `${String(hours)} h` : `${String(hours)} h ${String(rest)} min`;
}
