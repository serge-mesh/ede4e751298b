// The part of jsdom's API the build's page check uses (jsdom ships no types; remote-code.mjs).

declare module 'jsdom' {
  interface ScriptElement {
    readonly namespaceURI: string | null;
    readonly textContent: string | null;
    readonly outerHTML: string;
    getAttribute(name: string): string | null;
  }

  export class JSDOM {
    constructor(html?: string);
    readonly window: {
      readonly document: { querySelectorAll(selectors: 'script'): Iterable<ScriptElement> };
    };
  }
}
