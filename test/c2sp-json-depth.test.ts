import { describe, expect, it, vi } from 'vitest';
import * as protocol from '@dnsid-ai/protocol';
import {
  assertCanonicalJsonBytes,
  canonicalJson,
  C2spTlogParseError,
  C2spTlogResourceLimitError,
  C2spTlogVerificationError,
  parseJsonNoDuplicateMembers,
} from '@dnsid-ai/log-c2sp-tlog';

const bytes = (text: string) => new TextEncoder().encode(text);

describe('C2SP JSON nesting budget', () => {
  it.each(['array', 'object'])('matches Go value depths for %s containers', kind => {
    const wrap = (depth: number, leaf: string) => kind === 'array'
      ? '['.repeat(depth) + leaf + ']'.repeat(depth)
      : '{"x":'.repeat(depth) + leaf + '}'.repeat(depth);
    for (const leaf of ['0', 'null', 'true', '"text"', '[]', '{}']) {
      const allowed = wrap(64, leaf);
      expect(canonicalJson(parseJsonNoDuplicateMembers(bytes(allowed)))).toBe(allowed);
      const excessive = wrap(65, leaf);
      expect(() => parseJsonNoDuplicateMembers(bytes(excessive))).toThrow(C2spTlogResourceLimitError);
      expect(() => canonicalJson(JSON.parse(excessive))).toThrow(C2spTlogResourceLimitError);
      expect(() => assertCanonicalJsonBytes(bytes(excessive), JSON.parse(excessive))).toThrow(C2spTlogResourceLimitError);
    }
  });

  it('skips string contents, escaped quotes, backslashes, and member names', () => {
    const text = canonicalJson({ ['{["'.repeat(100)]: '\\"\\\\' + '[{]}'.repeat(20000) });
    expect(canonicalJson(parseJsonNoDuplicateMembers(bytes(text)))).toBe(text);
    const spaced = ' '.repeat(20) + '{ "\\"": [ "[]{}\\\\\\\"" ] }';
    expect(parseJsonNoDuplicateMembers(bytes(spaced))).toEqual(JSON.parse(spaced));
  });

  it.each([4200, 10000, 20000])('guards object serialization iteratively at depth %s', depth => {
    let value: unknown = 0;
    for (let i = 0; i < depth; i++) value = [value];
    expect(() => canonicalJson(value)).toThrow(C2spTlogResourceLimitError);
  });

  it('never relabels a parser RangeError as malformed JSON', () => {
    const cause = new RangeError('parser exhausted');
    const parser = vi.spyOn(protocol, 'parseJsonNoDuplicateMembers').mockImplementationOnce(() => { throw cause; });
    try {
      expect(() => parseJsonNoDuplicateMembers(bytes('{}'))).toThrow(C2spTlogResourceLimitError);
    } finally {
      parser.mockRestore();
    }
    const error = new C2spTlogResourceLimitError('limit', cause);
    expect(error).toBeInstanceOf(C2spTlogVerificationError);
    expect(error).not.toBeInstanceOf(C2spTlogParseError);
    expect(error).toMatchObject({ errorCategory: 'INVALID_EVIDENCE', transient: false, cause });
  });

  it('keeps malformed JSON and duplicate members as parse errors', () => {
    for (const text of ['{"x":', '{"x":1,"x":2}', '{"x":{"y":1,"y":2}}']) {
      expect(() => parseJsonNoDuplicateMembers(bytes(text))).toThrow(C2spTlogParseError);
    }
    expect(() => parseJsonNoDuplicateMembers(new Uint8Array([0xff]))).toThrow(C2spTlogParseError);
  });
});
