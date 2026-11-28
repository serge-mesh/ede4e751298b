// Test certificates, made with the openssl CLI in a temporary directory:
//
// - a test CA, trusted by the browsers the way a user trusts the LAN CA root (Firefox imports it
//   into its certificate store; Chromium trusts its key with --ignore-certificate-errors-spki-list);
// - the fake edge's certificate from it (IP 127.0.0.1), served with the CA so Chromium sees its key;
// - a certificate from it for another name, and a "rogue" CA nobody trusts with a certificate from
//   it: custom_ip targets whose TLS fails (browser-extension.md §5).

import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

export interface KeyPair {
  key: string;
  /** The certificate, then its CA's (what a server sends). */
  chain: string;
}

export interface TestCerts {
  dir: string;
  /** The trusted test CA, PEM. */
  caPem: string;
  /** Its DER, base64 (Firefox's certificate store takes it so). */
  caDerBase64: string;
  /** SHA-256 of its SubjectPublicKeyInfo, base64 (Chromium's SPKI list). */
  caSpki: string;
  /** The edge: IP 127.0.0.1 and `edge.test`, from the test CA. */
  edge: KeyPair;
  /** `elsewhere.test` only, from the test CA: valid, but for another name. */
  wrongName: KeyPair;
  /** `*.test` and every local IP, from a CA nobody trusts. */
  untrusted: KeyPair;
}

function openssl(args: string[], cwd: string): void {
  try {
    execFileSync('openssl', args, { cwd, stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (e) {
    throw new Error(`openssl ${args[0] ?? ''} failed (the browser tests need the openssl CLI)`, { cause: e });
  }
}

function makeCa(dir: string, name: string, cn: string): void {
  openssl(
    [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', `${name}.key`, '-out', `${name}.pem`, '-days', '7', '-subj', `/CN=${cn}`,
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    ],
    dir,
  );
}

function makeLeaf(dir: string, name: string, ca: string, san: string): KeyPair {
  writeFileSync(
    path.join(dir, `${name}.ext`),
    `subjectAltName=${san}\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n`,
  );
  openssl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`], dir);
  openssl(
    ['x509', '-req', '-in', `${name}.csr`, '-CA', `${ca}.pem`, '-CAkey', `${ca}.key`, '-set_serial', String(Date.now()), '-out', `${name}.pem`, '-days', '7', '-extfile', `${name}.ext`],
    dir,
  );
  const read = (f: string): string => readFileSync(path.join(dir, f), 'utf8');
  return { key: read(`${name}.key`), chain: read(`${name}.pem`) + read(`${ca}.pem`) };
}

/** Makes a fresh set (a few hundred ms). `localIps` go into the untrusted certificate. */
export function makeCerts(localIps: readonly string[]): TestCerts {
  const dir = mkdtempSync(path.join(tmpdir(), 'picket-certs-'));
  makeCa(dir, 'ca', 'Picket browser-test CA');
  makeCa(dir, 'rogue', 'Untrusted test CA');
  const edge = makeLeaf(dir, 'edge', 'ca', 'IP:127.0.0.1,DNS:edge.test');
  const wrongName = makeLeaf(dir, 'wrongname', 'ca', 'DNS:elsewhere.test');
  const untrusted = makeLeaf(dir, 'untrusted', 'rogue', ['DNS:*.test', 'IP:127.0.0.1', ...localIps.map((ip) => `IP:${ip}`)].join(','));
  const caPem = readFileSync(path.join(dir, 'ca.pem'), 'utf8');
  const ca = new X509Certificate(caPem);
  const spki = ca.publicKey.export({ type: 'spki', format: 'der' });
  return {
    dir,
    caPem,
    caDerBase64: ca.raw.toString('base64'),
    caSpki: createHash('sha256').update(spki).digest('base64'),
    edge,
    wrongName,
    untrusted,
  };
}
