// ESLint: typescript-eslint's strict type-checked rules for the extension's TypeScript, plus
// bans on HTML sinks (browser-extension.md §4: names and EXTRA-TEXT values are shown as text
// only) and on dynamic code.

import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const htmlSinks = [
  { property: 'innerHTML', message: 'Set text with textContent (browser-extension.md §4).' },
  { property: 'outerHTML', message: 'Set text with textContent (browser-extension.md §4).' },
  { property: 'insertAdjacentHTML', message: 'Build nodes with createElement (browser-extension.md §4).' },
  { property: 'createContextualFragment', message: 'Build nodes with createElement.' },
  { object: 'document', property: 'write', message: 'Build nodes with createElement.' },
  { object: 'document', property: 'writeln', message: 'Build nodes with createElement.' },
];

export default tseslint.config(
  { ignores: ['dist/', 'node_modules/', 'coverage/', 'test-results/', 'playwright-report/'] },
  js.configs.recommended,
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    extends: [...tseslint.configs.strictTypeChecked, ...tseslint.configs.stylisticTypeChecked],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
      globals: { ...globals.browser },
    },
    rules: {
      'no-restricted-properties': ['error', ...htmlSinks],
      'no-restricted-syntax': [
        'error',
        { selector: "CallExpression[callee.name='setTimeout'][arguments.0.type='Literal']", message: 'No string timers.' },
        { selector: "NewExpression[callee.name='Function']", message: 'No dynamic code.' },
      ],
      'no-implied-eval': 'off',
      '@typescript-eslint/no-implied-eval': 'error',
      'no-eval': 'error',
      'curly': 'error',
      'eqeqeq': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: false }],
      '@typescript-eslint/consistent-type-imports': 'error',
    },
  },
  {
    files: ['test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/unbound-method': 'off',
    },
  },
  {
    files: ['vitest.config.ts', 'playwright.config.ts'],
    extends: [...tseslint.configs.recommended],
  },
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: { globals: { ...globals.node } },
  },
);
