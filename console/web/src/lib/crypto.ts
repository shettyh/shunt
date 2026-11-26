/**
 * Browser-side WebCrypto helpers for minting real Shunt virtual keys (`sk-shunt-...` / `sk-mcp-...`)
 * and hashing them with SHA-256 before transmitting to Shunt Console's Channel 2 SyncedTable API.
 * Plaintext client keys never leave the user's browser except in the one-time copy dialog.
 */

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

export function generatePlaintextKey(prefix: 'sk-shunt-' | 'sk-mcp-' = 'sk-shunt-'): string {
  const bytes = new Uint8Array(36);
  crypto.getRandomValues(bytes);
  let body = '';
  for (let i = 0; i < bytes.length; i += 1) {
    body += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return `${prefix}${body}`;
}

export async function sha256Prefixed(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(hashBuf);
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return `sha256:${hex}`;
}

export function keyDisplayPrefix(plaintext: string): string {
  return `${plaintext.slice(0, 14)}…`;
}
