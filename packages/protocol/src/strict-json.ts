import { VerificationError, VerificationCode } from './errors.ts';
import { fromBase64Url, toBase64Url } from './utils.ts';

/** UTF-8 JSON with duplicate member rejection, including escaped member names. */
export function parseJsonNoDuplicateMembers(bytes: Uint8Array): unknown {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const stack: Array<Set<string> | null> = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '"') {
      const start = i++;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\') i++;
        i++;
      }
      let next = i + 1;
      while (/\s/.test(text[next] ?? '') && next < text.length) next++;
      if (text[next] === ':') {
        const key = JSON.parse(text.slice(start, i + 1)) as string;
        const keys = stack.at(-1);
        if (keys?.has(key)) throw new Error(`duplicate JSON member: ${key}`);
        keys?.add(key);
      }
    } else if (text[i] === '{') stack.push(new Set());
    else if (text[i] === '[') stack.push(null);
    else if (text[i] === '}' || text[i] === ']') stack.pop();
  }
  return JSON.parse(text);
}

/** Standalone JOSE limits: 1 MiB compact token, 16 KiB encoded header. */
export function parseCompactJose(token: string): { parts: [string, string, string]; header: Record<string, unknown>; payload: Uint8Array; signature: Uint8Array } {
  try {
    if (typeof token !== 'string' || token.length > 1024 * 1024) throw new Error('token too large');
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0]!.length > 16 * 1024) throw new Error('invalid compact structure');
    const decoded = parts.map(part => {
      if (!/^[A-Za-z0-9_-]*$/.test(part)) throw new Error('invalid base64url');
      const bytes = fromBase64Url(part);
      if (toBase64Url(bytes) !== part) throw new Error('noncanonical base64url');
      return bytes;
    });
    const header = parseJoseObject(decoded[0]!);
    if (typeof header.alg !== 'string' || !header.alg || typeof header.kid !== 'string' || !header.kid
      || ('typ' in header && typeof header.typ !== 'string') || 'crit' in header
      || ('b64' in header && header.b64 !== true)) throw new Error('unsupported protected header');
    return { parts: parts as [string, string, string], header, payload: decoded[1]!, signature: decoded[2]! };
  } catch (cause) {
    throw new VerificationError('malformed JOSE compact token', { code: VerificationCode.RecordInvalid, cause });
  }
}

export function parseJoseObject(bytes: Uint8Array): Record<string, unknown> {
  try {
    const value = parseJsonNoDuplicateMembers(bytes);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('expected JSON object');
    return value as Record<string, unknown>;
  } catch (cause) {
    throw new VerificationError('malformed JOSE JSON object', { code: VerificationCode.RecordInvalid, cause });
  }
}
