// The part of jsdom's API the build's page check uses (jsdom ships no types; remote-code.mjs).

declare module 'jsdom' {
  interface Element {
    readonly namespaceURI: string | null;
    readonly textContent: string | null;
    readonly outerHTML: string;
    getAttribute(name: string): string | null;
  }

  export class JSDOM {
    constructor(html?: string);
    readonly window: {
      readonly document: { querySelectorAll(selectors: string): Iterable<Element> };
    };
  }
}
