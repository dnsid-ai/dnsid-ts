import { fromBase64Url, toBase64Url } from '@identity-digital/dnsid-protocol';

/** Encodes bytes as unpadded base64url. */
export function b64url(bytes: Uint8Array): string {
  return toBase64Url(bytes);
}

/** Decodes a base64url string to bytes. */
export function fromB64url(s: string): Uint8Array {
  return fromBase64Url(s);
}

/** Decodes a standard base64 string to bytes. */
export function fromB64(s: string): Uint8Array {
  return fromBase64Url(s.replace(/\+/g, '-').replace(/\//g, '_'));
}
