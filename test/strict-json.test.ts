import { describe, expect, it } from 'vitest';
import { parseJsonNoDuplicateMembers } from '@identity-digital/dnsid-protocol';

const parse = (text: string) => parseJsonNoDuplicateMembers(new TextEncoder().encode(text));

describe('strict JSON member names', () => {
  it.each([
    '{"a":1,"a":2}',
    '{"a":1,"\\u0061":2}',
    '{"outer":{"a":1,"a":2}}',
    '[{"a":1,"\\u0061":2}]',
    '{"outer":[{"nested":{"a":1,"\\u0061":2}}]}',
  ])('rejects duplicate decoded names: %s', text => {
    expect(() => parse(text)).toThrow('duplicate JSON member: a');
  });

  it('keeps sibling object scopes separate and ignores punctuation inside strings', () => {
    const text = '{"a":[{"a":1},{"a":2}],"text":"\\\"a\\\": [{}]","escaped\\\"key":3}';
    expect(parse(text)).toEqual(JSON.parse(text));
  });
});
