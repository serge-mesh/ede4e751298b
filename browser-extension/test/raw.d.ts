// Page HTML imported as text by the page tests (Vite's `?raw`).
declare module '*.html?raw' {
  const text: string;
  export default text;
}
