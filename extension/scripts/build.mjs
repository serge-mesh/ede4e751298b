// Builds both targets (browser-extension.md §1) into dist/brave and dist/firefox: the pages
// (block, popup, options) and the background script with Vite, then each target's manifest.
// The code is the same for both; only the manifest differs. Output is unminified, with fixed
// file names, so builds are reproducible and reviewable.
//
// Version: PICKET_VERSION (the release's version) or package.json's.

import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';

import { manifest, TARGETS } from './manifest.mjs';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const dist = path.join(root, 'dist');

/** Browsers' minimums: Brave (Chromium 120+) and Firefox 128 ESR. */
const TARGET = ['chrome120', 'firefox128'];

export async function version() {
  const env = process.env['PICKET_VERSION'];
  if (env !== undefined && env !== '') {
    return env.replace(/^v/, '');
  }
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  return String(pkg.version);
}

/** @param {string} dir @returns {Promise<string[]>} */
async function files(dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...(await files(p)));
    } else {
      out.push(p);
    }
  }
  return out;
}

/**
 * No remote or dynamic code (README §2; security.md): scripts load only from the package, pages
 * hold no inline scripts, and nothing evaluates strings as code.
 * @param {string} dir
 */
async function checkNoRemoteCode(dir) {
  for (const f of await files(dir)) {
    const text = await readFile(f, 'utf8').catch(() => '');
    if (f.endsWith('.html')) {
      for (const m of text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi)) {
        const attrs = m[1] ?? '';
        const src = /\bsrc="([^"]*)"/.exec(attrs)?.[1];
        if (src === undefined || /^[a-z][a-z0-9+.-]*:|^\/\//i.test(src) || (m[2] ?? '').trim() !== '') {
          throw new Error(`${path.relative(root, f)}: inline or remote script`);
        }
      }
    }
    if (f.endsWith('.js') && /\beval\s*\(|\bnew\s+Function\s*\(|\bimportScripts\s*\(/.test(text)) {
      throw new Error(`${path.relative(root, f)}: dynamic code`);
    }
  }
}

export async function buildAll() {
  const ver = await version();
  const stage = path.join(dist, '.stage');
  await rm(dist, { recursive: true, force: true });
  const pages = path.join(root, 'src', 'pages');
  await build({
    configFile: false,
    root: pages,
    base: './',
    publicDir: path.join(root, 'public'),
    logLevel: 'warn',
    build: {
      outDir: stage,
      emptyOutDir: true,
      target: TARGET,
      minify: false,
      modulePreload: false,
      reportCompressedSize: false,
      rolldownOptions: {
        input: {
          block: path.join(pages, 'block.html'),
          popup: path.join(pages, 'popup.html'),
          options: path.join(pages, 'options.html'),
        },
        output: {
          entryFileNames: 'assets/[name].js',
          chunkFileNames: 'assets/[name].js',
          // The pages share one stylesheet.
          assetFileNames: (info) => (info.names.some((n) => n.endsWith('.css')) ? 'assets/style.css' : 'assets/[name][extname]'),
        },
      },
    },
  });
  // The background script is one classic script (a Chromium service worker without
  // `type: module`, and a Firefox background script), so it is built on its own as an IIFE.
  await build({
    configFile: false,
    root,
    publicDir: false,
    logLevel: 'warn',
    build: {
      outDir: stage,
      emptyOutDir: false,
      target: TARGET,
      minify: false,
      modulePreload: false,
      reportCompressedSize: false,
      lib: {
        entry: path.join(root, 'src', 'background', 'index.ts'),
        formats: ['iife'],
        name: 'picketBackground',
        fileName: () => 'background.js',
      },
    },
  });
  await checkNoRemoteCode(stage);
  for (const target of TARGETS) {
    const out = path.join(dist, target);
    await mkdir(out, { recursive: true });
    await cp(stage, out, { recursive: true });
    await writeFile(path.join(out, 'manifest.json'), `${JSON.stringify(manifest(target, ver), null, 2)}\n`);
  }
  await rm(stage, { recursive: true, force: true });
  return ver;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const ver = await buildAll();
  console.log(`built ${TARGETS.map((t) => `dist/${t}`).join(' and ')} (version ${ver})`);
}
