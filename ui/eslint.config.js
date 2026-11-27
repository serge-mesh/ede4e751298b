import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

// Text from outside core is rendered only as React text (core.md §12): these patterns are
// errors everywhere, so the rule can't be broken by accident.
const htmlSinks = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: "Never render HTML: outside text is shown as React text only (core.md §12).",
  },
  {
    selector: "AssignmentExpression > MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
    message: "Never assign innerHTML/outerHTML (core.md §12).",
  },
  {
    selector: "CallExpression[callee.property.name=/^(insertAdjacentHTML|write|writeln)$/]",
    message: "Never write HTML strings into the document (core.md §12).",
  },
  {
    selector: "CallExpression[callee.name='eval'], NewExpression[callee.name='Function']",
    message: "No eval: the CSP forbids it (core.md §12).",
  },
];

export default tseslint.config(
  { ignores: ["dist", "node_modules", "src/api/schema.d.ts", "coverage"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { ecmaVersion: 2023, globals: globals.browser },
    plugins: { "react-hooks": reactHooks, "react-refresh": reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": "off",
      "no-restricted-syntax": ["error", ...htmlSinks],
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" },
      ],
    },
  },
  {
    files: ["*.config.{js,ts}"],
    languageOptions: { globals: globals.node },
  },
);
