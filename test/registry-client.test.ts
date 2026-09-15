import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_REGISTRY_URL,
  PreparedEventSubmissionError,
  RegistryClient,
  awaitRegistryManagedPublication,
  publishClientControlledRecord,
  publishToRegistry,
} from '@identity-digital/dnsid-registry';
import { ArgumentError, jwkThumbprint, toBase64Url } from '@identity-digital/dnsid-protocol';
import type { IdentityConfig, DnsIdJWK, KeyProvider } from '@identity-digital/dnsid-protocol';
import { DRAFT01_UNSIGNED_CANONICAL } from './fixtures/draft01-record-vectors.ts';

const VALID_CANONICAL = DRAFT01_UNSIGNED_CANONICAL;
const PRODUCT_CANONICAL = VALID_CANONICAL.replace(
  'gi=example.com;',
  'gi=example.com;ka=90d;',
);

async function sha256Hex(value: Uint8Array): Promise<string> {
  const input = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

function client(fetchMock: typeof fetch = fetch): RegistryClient {
  const withRegistration = (async (url: string, init?: RequestInit) => {
    const response = await fetchMock(url, init);
    if (!url.endsWith('/status')) return response;
    if (response.status === 404) {
      return new Response(JSON.stringify({ id: 'agent-1', domain: 'agent.example.com', status: 'READY', managed: 'self', dns_published: false }));
    }
    const raw = await response.clone().json() as Record<string, unknown>;
    return new Response(JSON.stringify({ id: 'agent-1', domain: 'agent.example.com', managed: 'self', ...raw }), {
      status: response.status,
      headers: response.headers,
    });
  }) as typeof fetch;
  return new RegistryClient({ baseUrl: 'https://registry.example', fetch: withRegistration });
}

const TEST_JWK: DnsIdJWK = {
  kty: 'OKP',
  kid: 'test-key-1',
  alg: 'EdDSA',
  use: 'sig',
  crv: 'Ed25519',
  x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};
const OTHER_TEST_JWK: DnsIdJWK = {
  ...TEST_JWK,
  kid: 'test-key-2',
  x: toBase64Url(new Uint8Array(32).fill(1)),
};
const JWKS_SHAPED_JWK = {
  ...TEST_JWK,
  keys: [{ ...TEST_JWK, d: 'private' }],
} as DnsIdJWK;

async function liveChallengeMessage(
  challenge: string,
  agentId = 'agent-live-1',
  fqdn = 'live.example',
  publicKeyJwk = TEST_JWK,
): Promise<string> {
  return toBase64Url(new TextEncoder().encode(JSON.stringify({
    protocol: 'dnsid-live-provisioning-pop/v1',
    org_id: 'org-1',
    agent_id: agentId,
    fqdn,
    key_id: await jwkThumbprint(publicKeyJwk),
    nonce: challenge,
    expires_at: '2030-01-01T00:00:00Z',
  })));
}

const BASE_CONFIG: IdentityConfig = {
  domain: 'agent.example.com',
  governanceId: 'example.com',
  logRef: 'microledger:abc123',
  statusUrl: 'https://agent.example.com/status',
  ekUrl: 'https://example.com/entity-jwks.json',
  kuUrl: 'https://agent.example.com/jwks.json',
};

function keyProvider(jwk: DnsIdJWK = TEST_JWK, sig = new Uint8Array([1, 2, 3])): KeyProvider {
  return {
    signingKey: vi.fn().mockResolvedValue(jwk),
    jwk: vi.fn().mockResolvedValue(jwk),
    listKeyIds: vi.fn().mockResolvedValue([jwk.kid]),
    sign: vi.fn().mockResolvedValue(sig),
    signKey: vi.fn().mockResolvedValue(sig),
    generateKey: vi.fn(),
    activate: vi.fn(),
    supersede: vi.fn(),
    purge: vi.fn(),
  };
}

describe('RegistryClient', () => {
  it.each([
    'http://registry.example',
    'https://user:secret@registry.example',
    'https://registry.example?token=secret',
    'https://registry.example#fragment',
  ])('rejects unsafe registry base URL %s', (baseUrl) => {
    expect(() => new RegistryClient({ baseUrl })).toThrow(ArgumentError);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('uses https://api.dnsid.ai as the default base URL when none is provided', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toMatch(/^https:\/\/api\.dnsid\.ai\//);
      return new Response(JSON.stringify({ id: 'agent-1', status: 'PENDING', managed: 'self' }));
    }) as unknown as typeof fetch;

    const registry = new RegistryClient({ fetch: fetchMock });
    await registry.getAgentStatus('agent.example.com');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.dnsid.ai/api/v1/agent/agent.example.com/status',
      expect.anything(),
    );
  });

  it('exports DEFAULT_REGISTRY_URL constant matching the default', () => {
    expect(DEFAULT_REGISTRY_URL).toBe('https://api.dnsid.ai');
  });

  it('validates server canonical content and submits a bare draft-01 signature during publication', async () => {
    const sign = vi.fn(async () => 'test-signature');
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/record')) {
        expect(JSON.parse(String(init?.body))).toEqual({ signingKid: 'test-key-1' });
        return new Response(JSON.stringify({
          fqdn: 'agent.example.com',
          canonicalContent: VALID_CANONICAL,
          signingKid: 'test-key-1',
          tags: { v: 'dnsid-draft-01' },
          expiresAt: '2026-05-15T00:00:00.000Z',
        }));
      }
      if (url.endsWith('/signature')) {
        expect(JSON.parse(String(init?.body))).toEqual({ signature: 'test-signature' });
        return new Response(JSON.stringify({
          fqdn: 'agent.example.com',
          status: 'ACTIVE',
          records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
        }));
      }
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    const published = await client(fetchMock).publishTxtRecordWithSigner(
      'agent.example.com',
      sign,
      {
        expectedCanonicalContent: VALID_CANONICAL,
        agentFQDN: 'agent.example.com',
        signingKid: 'test-key-1',
      },
    );

    expect(sign).toHaveBeenCalledOnce();
    const signedBytes = (sign as unknown as { mock: { calls: [Uint8Array][] } }).mock.calls[0]![0];
    expect(new TextDecoder().decode(signedBytes)).toBe(VALID_CANONICAL);
    expect(published.domain).toBe('agent.example.com');
  });

  it('accepts registry-managed unknown canonical tags when comparing expected known tags', async () => {
    const sign = vi.fn(async () => 'test-signature');
    const registryCanonical = `${VALID_CANONICAL};zz=registry-managed`;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/record')) {
        return new Response(JSON.stringify({ canonicalContent: registryCanonical, signingKid: 'test-key-1' }));
      }
      if (url.endsWith('/signature')) {
        expect(JSON.parse(String(init?.body))).toEqual({ signature: 'test-signature' });
        return new Response(JSON.stringify({
          fqdn: 'agent.example.com',
          status: 'ACTIVE',
          records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
        }));
      }
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).publishTxtRecordWithSigner(
      'agent.example.com',
      sign,
      {
        expectedCanonicalContent: VALID_CANONICAL,
        agentFQDN: 'agent.example.com',
        signingKid: 'test-key-1',
      },
    )).resolves.toMatchObject({ domain: 'agent.example.com' });
    const signedBytes = (sign as unknown as { mock: { calls: [Uint8Array][] } }).mock.calls[0]![0];
    expect(new TextDecoder().decode(signedBytes)).toBe(registryCanonical);
  });

  it('accepts registry-managed exp canonical tags when comparing expected known tags', async () => {
    const sign = vi.fn(async () => 'test-signature');
    const registryCanonical = `ek=https://example.com/entity-jwks.json;exp=2026-05-15T00:00:00Z;gi=example.com;ku=https://agent.example.com/jwks.json;lr=microledger:abc123;su=https://agent.example.com/status;v=dnsid-draft-01`;
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/record')) return new Response(JSON.stringify({ canonicalContent: registryCanonical, signingKid: 'test-key-1' }));
      if (url.endsWith('/signature')) {
        return new Response(JSON.stringify({
          fqdn: 'agent.example.com',
          status: 'ACTIVE',
          records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
        }));
      }
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).publishTxtRecordWithSigner(
      'agent.example.com',
      sign,
      { expectedCanonicalContent: VALID_CANONICAL, agentFQDN: 'agent.example.com', signingKid: 'test-key-1' },
    )).resolves.toMatchObject({ domain: 'agent.example.com' });
  });

  it('rejects verification-only profiles before invoking the signer', async () => {
    const sign = vi.fn(async () => 'test-signature');
    const dnsid1Canonical = VALID_CANONICAL.replace('v=dnsid-draft-01', 'v=DNSid1');
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      canonicalContent: dnsid1Canonical,
      signingKid: 'test-key-1',
    }))) as unknown as typeof fetch;

    await expect(client(fetchMock).publishTxtRecordWithSigner(
      'agent.example.com', sign,
      { expectedCanonicalContent: dnsid1Canonical, agentFQDN: 'agent.example.com', signingKid: 'test-key-1' },
    )).rejects.toThrow(/unsupported DNSid publish profile/);
    expect(sign).not.toHaveBeenCalled();
  });

  it('rejects registry canonicalContent mismatch when an expected canonical record is supplied', async () => {
    const sign = vi.fn(async () => 'test-signature');
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      canonicalContent: VALID_CANONICAL.replace('/status', '/other-status'),
      signingKid: 'test-key-1',
    }))) as unknown as typeof fetch;

    await expect(client(fetchMock).publishTxtRecordWithSigner(
      'agent.example.com',
      sign,
      {
        expectedCanonicalContent: VALID_CANONICAL,
        agentFQDN: 'agent.example.com',
        signingKid: 'test-key-1',
      },
    )).rejects.toThrow(/does not match/);
    expect(sign).not.toHaveBeenCalled();
  });

  it('publishToRegistry compares registry content against local known tags and signs registry bytes', async () => {
    const kp = keyProvider();
    const registryCanonical = `${VALID_CANONICAL};zz=registry-managed`;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/record')) return new Response(JSON.stringify({ canonicalContent: registryCanonical, signingKid: 'test-key-1' }));
      if (url.endsWith('/signature')) {
        expect(JSON.parse(String(init?.body))).toEqual({ signature: 'AQID' });
        return new Response(JSON.stringify({
          fqdn: 'agent.example.com',
          status: 'ACTIVE',
          records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
        }));
      }
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(publishToRegistry({
      config: BASE_CONFIG,
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
    })).resolves.toMatchObject({ domain: 'agent.example.com' });
    const signedBytes = (kp.sign as ReturnType<typeof vi.fn>).mock.calls[0]![0] as Uint8Array;
    expect(new TextDecoder().decode(signedBytes)).toBe(registryCanonical);
  });

  it('publishToRegistry rejects when the registry omits signingKid', async () => {
    const kp = keyProvider();
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/record')) return new Response(JSON.stringify({ canonicalContent: VALID_CANONICAL }));
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(publishToRegistry({
      config: BASE_CONFIG,
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
    })).rejects.toThrow(/signingKid must be a non-empty string/);
    expect(kp.sign).not.toHaveBeenCalled();
  });

  it('publishToRegistry rejects a registry signingKid that differs from the active entity key', async () => {
    const kp = keyProvider();
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/record')) {
        return new Response(JSON.stringify({ canonicalContent: VALID_CANONICAL, signingKid: 'other-key' }));
      }
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(publishToRegistry({
      config: BASE_CONFIG,
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
    })).rejects.toThrow(/different active signing kid/);
    expect(kp.sign).not.toHaveBeenCalled();
  });

  it('publishToRegistry uses the entity key provider for kid validation and signing', async () => {
    const entityJwk = { ...TEST_JWK, kid: 'entity-key-1' };
    const entityProvider = keyProvider(entityJwk, new Uint8Array([4, 5, 6]));
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/record')) return new Response(JSON.stringify({ canonicalContent: VALID_CANONICAL, signingKid: 'entity-key-1' }));
      if (url.endsWith('/signature')) {
        expect(JSON.parse(String(init?.body))).toEqual({ signature: 'BAUG' });
        return new Response(JSON.stringify({
          fqdn: 'agent.example.com',
          status: 'ACTIVE',
          records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
        }));
      }
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(publishToRegistry({
      config: BASE_CONFIG,
      entityKeyProvider: entityProvider,
      registryClient: client(fetchMock),
    })).resolves.toMatchObject({ domain: 'agent.example.com' });
  });

  it('publishToRegistry accepts draft-01 canonical content from the registry and signs registry bytes', async () => {
    const kp = keyProvider();
    const registryCanonical = VALID_CANONICAL;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/record')) return new Response(JSON.stringify({ canonicalContent: registryCanonical, signingKid: 'test-key-1' }));
      if (url.endsWith('/signature')) {
        expect(JSON.parse(String(init?.body))).toEqual({ signature: 'AQID' });
        return new Response(JSON.stringify({
          fqdn: 'agent.example.com',
          status: 'ACTIVE',
          records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
        }));
      }
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(publishToRegistry({
      config: BASE_CONFIG,
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
    })).resolves.toMatchObject({ domain: 'agent.example.com' });
    const signedBytes = (kp.sign as ReturnType<typeof vi.fn>).mock.calls[0]![0] as Uint8Array;
    expect(new TextDecoder().decode(signedBytes)).toBe(registryCanonical);
  });

  it('allows a custom registry publication config to explicitly omit ka', async () => {
    const kp = keyProvider();
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/record')) return new Response(JSON.stringify({ canonicalContent: VALID_CANONICAL, signingKid: 'test-key-1' }));
      if (url.endsWith('/signature')) return new Response(JSON.stringify({
        fqdn: 'agent.example.com',
        status: 'ready_for_publication',
        records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
      }));
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(publishClientControlledRecord({
      config: BASE_CONFIG,
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
      effectiveMaxKeyAge: null,
    })).resolves.toMatchObject({ domain: 'agent.example.com' });
  });

  it('includes ka only when supplied by authoritative publication config', async () => {
    const kp = keyProvider();
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/record')) return new Response(JSON.stringify({ canonicalContent: PRODUCT_CANONICAL, signingKid: 'test-key-1' }));
      if (url.endsWith('/signature')) return new Response(JSON.stringify({
        fqdn: 'agent.example.com',
        status: 'ready_for_publication',
        records: [{ name: '_dnsid.agent.example.com', value: 'v=dnsid-draft-01;...', ttl: 300 }],
      }));
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(publishClientControlledRecord({
      config: { ...BASE_CONFIG, maxKeyAge: '90d' },
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
    })).resolves.toMatchObject({ domain: 'agent.example.com' });
  });

  it('publishToRegistry rejects entity signing keys missing draft-01 alg before signing', async () => {
    const missingAlgJwk: DnsIdJWK = {
      kty: 'OKP',
      kid: 'test-key-1',
      use: 'sig',
      crv: 'Ed25519',
      x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    };
    const kp = keyProvider(missingAlgJwk);
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      domain: 'agent.example.com', status: 'READY', managed: 'self',
    }))) as unknown as typeof fetch;

    await expect(publishToRegistry({
      config: BASE_CONFIG,
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
    })).rejects.toThrow(/missing alg/);
    expect(kp.sign).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('publishToRegistry rejects unsupported publish profiles before signing', async () => {
    const kp = keyProvider();
    await expect(publishToRegistry({
      config: { ...BASE_CONFIG, publishProfile: 'DNSid1' },
      entityKeyProvider: kp,
      registryClient: client(),
    })).rejects.toThrow(/unsupported DNSid publish profile/);
    expect(kp.sign).not.toHaveBeenCalled();
  });

  it('rejects non-canonical registry canonicalContent before signing', async () => {
    const sign = vi.fn(async () => 'test-signature');
    const nonCanonical = VALID_CANONICAL.replace(
      'gi=example.com;ku=https://agent.example.com/jwks.json',
      'ku=https://agent.example.com/jwks.json;gi=example.com',
    );
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      canonicalContent: nonCanonical,
      signingKid: 'test-key-1',
    }))) as unknown as typeof fetch;

    await expect(client(fetchMock).publishTxtRecordWithSigner(
      'agent.example.com',
      sign,
      { expectedCanonicalContent: VALID_CANONICAL, agentFQDN: 'agent.example.com', signingKid: 'test-key-1' },
    )).rejects.toThrow(/invalid/);
    expect(sign).not.toHaveBeenCalled();
  });

  it('sends capabilities_url during registration', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/status')) {
        return new Response(JSON.stringify({ domain: 'agent.example.com', status: 'PENDING', managed: 'self' }));
      }
      expect(JSON.parse(String(init?.body))).toMatchObject({
        domain: 'agent.example.com',
        capabilities_url: 'https://agent.example.com/.well-known/agent-card.json',
      });
      expect(JSON.parse(String(init?.body))).not.toHaveProperty('capabilitiesUrl');
      return new Response(JSON.stringify({
        domain: 'agent.example.com',
        status: 'PENDING',
        oidc_issuer_url: 'https://issuer.example.com/live',
      }), { status: 201 });
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).registerAgent({
      domain: 'agent.example.com',
      environment: 'production',
      capabilitiesUrl: 'https://agent.example.com/.well-known/agent-card.json',
      idempotencyKey: 'registration-1',
    })).resolves.toMatchObject({
      domain: 'agent.example.com',
      registryStatus: 'PENDING',
      publicationAuthority: 'client',
      oidcIssuerUrl: 'https://issuer.example.com/live',
    });
  });

  it('uses the product name field and does not send unsupported arbitrary metadata', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/status')) {
        return new Response(JSON.stringify({ domain: 'agent.example.com', status: 'PENDING', managed: 'self' }));
      }
      const body = JSON.parse(String(init?.body));
      expect(body).toMatchObject({ domain: 'agent.example.com', name: 'Procurement Bot' });
      expect(body).not.toHaveProperty('metadata');
      return new Response(JSON.stringify({ domain: 'agent.example.com', status: 'PENDING' }), { status: 201 });
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).registerAgent({
      domain: 'agent.example.com',
      environment: 'production',
      name: 'Procurement Bot',
      metadata: { ignored: true },
      idempotencyKey: 'registration-1',
    })).resolves.toMatchObject({ domain: 'agent.example.com' });
  });

  it('rejects a non-201 ordinary registration response', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ domain: 'agent.example.com' }), { status: 202 })) as unknown as typeof fetch;
    await expect(client(fetchMock).registerAgent({ domain: 'agent.example.com', environment: 'production', idempotencyKey: 'registration-1' }))
      .rejects.toThrow('expected HTTP 201');
  });

  it('unregisters an agent and treats unsupported or absent agents as no-ops', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.method).toBe('DELETE');
      return new Response('not found', { status: 404 });
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).unregisterAgent('agent.example.com')).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      'https://registry.example/api/v1/agent/agent.example.com',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });

  it('revokes the immutable agent identity through the registry-owned lifecycle flow', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://registry.example/api/v1/agent/agent.example.com/revoke');
      expect(init?.method).toBe('POST');
      expect(JSON.parse(String(init?.body))).toEqual({
        agent_id: 'agent-immutable-1',
        reason: 'owner_request',
      });
      return new Response(JSON.stringify({ id: 'agent-immutable-1', status: 'REVOKED' }));
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).revokeAgent(
      'agent.example.com',
      'agent-immutable-1',
      'owner_request',
    )).resolves.toMatchObject({ id: 'agent-immutable-1', registryStatus: 'REVOKED' });
  });

  it.each([
    ['', 'owner_request'],
    [' agent-immutable-1 ', 'owner_request'],
    ['agent-immutable-1', 'invalid_reason'],
  ])('rejects invalid revocation input before posting', async (agentId, reason) => {
    const fetchMock = vi.fn() as unknown as typeof fetch;

    await expect(client(fetchMock).revokeAgent(
      'agent.example.com',
      agentId,
      reason as 'owner_request',
    )).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns the distinct 202 Live provisioning response with a validated assigned domain', async () => {
    const challengeMessage = await liveChallengeMessage('challenge-1');
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://registry.example/api/v1/agent');
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe('live-1');
      expect(JSON.parse(String(init?.body))).toMatchObject({
        tier: 'live',
        managed: true,
        environment: 'production',
        public_key: TEST_JWK,
      });
      return new Response(JSON.stringify({
        request_id: 'live-1', agent_id: 'agent-live-1', status: 'challenge_pending',
        challenge: 'challenge-1', challenge_message: challengeMessage,
      }), { status: 202 });
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).registerLiveAgent({ publicKeyJwk: TEST_JWK }, 'live-1')).resolves.toMatchObject({
      requestId: 'live-1', agentId: 'agent-live-1', status: 'challenge_pending',
      challenge: 'challenge-1', challengeMessage, domain: 'live.example',
      challengeTranscript: { agentId: 'agent-live-1', nonce: 'challenge-1', fqdn: 'live.example' },
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('accepts a valid Live replay after the challenge is complete', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      request_id: 'live-1', agent_id: 'agent-live-1', status: 'provider_deferred',
      challenge: '', challenge_message: '',
    }), { status: 202 })) as unknown as typeof fetch;

    const response = await client(fetchMock).registerLiveAgent({ publicKeyJwk: TEST_JWK }, 'live-1');
    expect(response).toMatchObject({ status: 'provider_deferred', challenge: '', challengeMessage: '' });
    expect(response).not.toHaveProperty('domain');
    expect(response).not.toHaveProperty('challengeTranscript');
  });

  it('rejects invalid Live inputs before making a request', async () => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const registry = client(fetchMock);
    await expect(registry.registerLiveAgent({ publicKeyJwk: TEST_JWK }, undefined as never))
      .rejects.toThrow('idempotencyKey is required');
    await expect(registry.registerLiveAgent({ publicKeyJwk: {
      kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: 'ec-1', x: 'AQ', y: 'Ag',
    } }, 'live-1')).rejects.toThrow('OKP/Ed25519');
    await expect(registry.reissueLiveProof(
      'live.example', 'live-1', { ...TEST_JWK, d: 'private' } as DnsIdJWK,
    )).rejects.toThrow('private JWK member d');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a Live response whose transcript does not match its outer challenge', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      request_id: 'live-1', agent_id: 'agent-live-1', status: 'challenge_pending',
      challenge: 'challenge-1', challenge_message: await liveChallengeMessage('other-challenge'),
    }), { status: 202 })) as unknown as typeof fetch;

    await expect(client(fetchMock).registerLiveAgent({ publicKeyJwk: TEST_JWK }, 'live-1'))
      .rejects.toThrow('outer response binding mismatch');
  });

  it('retires an immutable agent identity', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://registry.example/api/v1/agent/agent.example.com/retire');
      expect(init?.method).toBe('POST');
      expect(JSON.parse(String(init?.body))).toEqual({ agent_id: 'agent-1' });
      return new Response(JSON.stringify({ id: 'agent-1', status: 'RETIRED', status_note: 'agent retired' }));
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).retireAgent('agent.example.com', 'agent-1'))
      .resolves.toMatchObject({ id: 'agent-1', registryStatus: 'RETIRED' });
  });

  it('rejects client signing when the registry controls publication', async () => {
    const kp = keyProvider();
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      domain: 'agent.example.com', status: 'READY', managed: 'dnsid', dns_published: true,
    }))) as unknown as typeof fetch;

    await expect(publishClientControlledRecord({
      config: BASE_CONFIG,
      entityKeyProvider: kp,
      registryClient: client(fetchMock),
    })).rejects.toThrow('registry controls accountable-entity publication');
    expect(kp.signingKey).not.toHaveBeenCalled();
  });

  it('waits for registry-managed DNS publication and verifies the observed record', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      domain: 'agent.example.com', status: 'READY', managed: 'dnsid', dns_published: true,
    }))) as unknown as typeof fetch;
    const identityManager = {
      verifyPublicationEvidence: vi.fn(async () => ({
        record: { v: 'dnsid-draft-01', serialize: () => 'v=dnsid-draft-01;...' },
        dnsTTL: 300,
        registryStatus: { state: 'ACTIVE' as const, lastTransitionAt: new Date('2026-05-15T00:00:00Z') },
      })),
    };

    await expect(awaitRegistryManagedPublication({
      domain: 'agent.example.com',
      registryClient: client(fetchMock),
      identityManager,
    })).resolves.toMatchObject({
      ownerName: '_dnsid.agent.example.com',
      txtRecord: 'v=dnsid-draft-01;...',
      ttl: 300,
      publicationStatus: 'READY',
      protocolStatus: { state: 'ACTIVE' },
    });
    expect(identityManager.verifyPublicationEvidence).toHaveBeenCalledWith('agent.example.com');
  });

  it('rejects a verified registry-managed record with a verification-only selector', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      domain: 'agent.example.com', status: 'READY', managed: 'dnsid', dns_published: true,
    }))) as unknown as typeof fetch;
    const identityManager = {
      verifyPublicationEvidence: vi.fn(async () => ({
        record: { v: 'DNSid1', serialize: () => 'v=DNSid1;...' },
        dnsTTL: 300,
        registryStatus: { state: 'ACTIVE' as const, lastTransitionAt: new Date('2026-05-15T00:00:00Z') },
      })),
    };

    await expect(awaitRegistryManagedPublication({
      domain: 'agent.example.com', registryClient: client(fetchMock), identityManager,
    })).rejects.toThrow(/unexpected profile DNSid1/);
  });

  it('prepares and submits exact C2SP key-rotation bytes', async () => {
    const preparedBytes = new TextEncoder().encode('{"type":"KEY_ROTATION"}');
    const completedBytes = new TextEncoder().encode('{"type":"KEY_ROTATION","sigs":{}}');
    const completedHash = await sha256Hex(completedBytes);
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get('Idempotency-Key')).toBe('rotation-1');
      if (url.endsWith('/prepare')) {
        expect(JSON.parse(String(init?.body))).toMatchObject({
          previous_key_id: 'old-key',
          public_key: TEST_JWK,
        });
        return new Response(preparedBytes, { headers: { 'DNSID-Log-Reference': 'c2sp-tlog:test:stream' } });
      }
      expect(url).toBe('https://registry.example/api/v1/agent/agent.example.com/tlog/events');
      expect(new Uint8Array(init?.body as ArrayBuffer)).toEqual(completedBytes);
      return new Response(JSON.stringify({
        state: 'accepted', entry_hash: completedHash, index: 7,
        lr: 'c2sp-tlog:public:https://log.example#agent.example.com@7', key_id: 'new-key',
      }));
    }) as unknown as typeof fetch;
    const registry = client(fetchMock);

    await expect(registry.prepareKeyRotation('agent.example.com', {
      previousKeyId: 'old-key', publicKey: TEST_JWK,
    }, 'rotation-1')).resolves.toEqual({
      entryBytes: preparedBytes,
      logReference: 'c2sp-tlog:test:stream',
    });
    await expect(registry.submitPreparedEvent('agent.example.com', completedBytes, 'rotation-1')).resolves.toMatchObject({
      state: 'accepted', entryHash: completedHash, index: 7,
      logRef: 'c2sp-tlog:public:https://log.example#agent.example.com@7', keyId: 'new-key',
    });
  });

  it('hashes the exact submitted Uint8Array slice before accepting the response', async () => {
    const backing = new TextEncoder().encode('prefix:{"type":"ISSUANCE"}:suffix');
    const entryBytes = backing.subarray(7, backing.length - 7);
    const entryHash = await sha256Hex(entryBytes);
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(new Uint8Array(init?.body as ArrayBuffer)).toEqual(entryBytes);
      return new Response(JSON.stringify({
        state: 'accepted',
        entry_hash: entryHash,
        index: 0,
        lr: 'c2sp-tlog:public:https://log.example#agent.example.com@0',
      }));
    }) as unknown as typeof fetch;

    await expect(client(fetchMock).submitPreparedEvent('agent.example.com', entryBytes, 'issuance-1'))
      .resolves.toMatchObject({ state: 'accepted', entryHash, index: 0 });
  });

  it.each([
    ['0'.repeat(64), 'different prepared-event entry_hash'],
    ['sha256:abc', 'accepted entry_hash must be lowercase SHA-256 hex'],
    ['A'.repeat(64), 'accepted entry_hash must be lowercase SHA-256 hex'],
  ])('rejects an accepted response whose entry_hash is not the exact submitted SHA-256 (%s)', async (entryHash, message) => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      state: 'accepted',
      entry_hash: entryHash,
      index: 0,
      lr: 'c2sp-tlog:public:https://log.example#agent.example.com@0',
    }))) as unknown as typeof fetch;

    await expect(client(fetchMock).submitPreparedEvent('agent.example.com', new Uint8Array([1]), 'issuance-1'))
      .rejects.toThrow(message);
  });

  it('prepares ISSUANCE without parsing or reserializing the canonical response', async () => {
    const preparedBytes = new TextEncoder().encode('{"v":1, "signed_extension":"preserve whitespace"}\n');
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://registry.example/api/v1/agent/agent.example.com/tlog/issuance/prepare');
      expect(init?.method).toBe('POST');
      expect(init?.body).toBeUndefined();
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe('issuance-1');
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer agent-token');
      return new Response(preparedBytes, {
        headers: { 'DNSID-Log-Reference': 'c2sp-tlog:testnet:https://log.example/dnsid#agent.example.com' },
      });
    }) as unknown as typeof fetch;
    const registry = new RegistryClient({
      baseUrl: 'https://registry.example',
      token: 'agent-token',
      fetch: fetchMock,
    });

    await expect(registry.prepareIssuance('agent.example.com', 'issuance-1')).resolves.toEqual({
      entryBytes: preparedBytes,
      logReference: 'c2sp-tlog:testnet:https://log.example/dnsid#agent.example.com',
    });
  });

  it.each([
    ['', 'issuance-1', 'domain is required'],
    [' agent.example.com', 'issuance-1', 'domain is required'],
    ['agent.example.com', '', 'idempotencyKey is required'],
    ['agent.example.com', ' issuance-1', 'surrounding whitespace'],
    ['agent.example.com', 'issuance-1\n', 'surrounding whitespace'],
    ['agent.example.com', 'x'.repeat(201), 'must not exceed 200 UTF-8 bytes'],
    ['agent.example.com', 'é'.repeat(101), 'must not exceed 200 UTF-8 bytes'],
  ])('rejects invalid ISSUANCE preparation input', async (domain, idempotencyKey, message) => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    await expect(new RegistryClient({ fetch: fetchMock }).prepareIssuance(domain, idempotencyKey)).rejects.toThrow(message);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['key rotation', (registry: RegistryClient, key: string) => registry.prepareKeyRotation('agent.example.com', {
      previousKeyId: 'old-key', publicKey: TEST_JWK,
    }, key)],
    ['prepared submission', (registry: RegistryClient, key: string) => registry.submitPreparedEvent(
      'agent.example.com', new Uint8Array([1]), key,
    )],
  ])('applies the shared idempotency-key validation to %s', async (_name, call) => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const registry = new RegistryClient({ fetch: fetchMock });
    await expect(call(registry, ' idempotency-key')).rejects.toThrow('surrounding whitespace');
    await expect(call(registry, 'é'.repeat(101))).rejects.toThrow('200 UTF-8 bytes');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('requires the bound log reference on an ISSUANCE preparation response', async () => {
    const fetchMock = vi.fn(async () => new Response(new Uint8Array([1]))) as unknown as typeof fetch;
    await expect(client(fetchMock).prepareIssuance('agent.example.com', 'issuance-1'))
      .rejects.toThrow('DNSID-Log-Reference is required');
  });

  it.each([
    [{ state: 'pending', entry_hash: 'sha256:pending' }, { state: 'pending', entryHash: 'sha256:pending' }],
    [{ state: 'rejected', entry_hash: 'sha256:rejected', error_code: 'stale_preparation' }, { state: 'rejected', entryHash: 'sha256:rejected', errorCode: 'stale_preparation' }],
  ])('accepts non-terminal prepared-event submission result %j', async (body, expected) => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(body))) as unknown as typeof fetch;
    const result = await client(fetchMock).submitPreparedEvent('agent.example.com', new Uint8Array([1]), 'rotation-1');
    expect(result).toMatchObject(expected);
    expect(result.index).toBeUndefined();
    expect(result.logRef).toBeUndefined();
  });

  it('rejects unknown prepared-event submission states', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ state: 'indeterminate', entry_hash: 'sha256:abc' }))) as unknown as typeof fetch;
    await expect(client(fetchMock).submitPreparedEvent('agent.example.com', new Uint8Array([1]), 'rotation-1'))
      .rejects.toThrow('unsupported state');
  });

  it.each([
    [
      409,
      { error: 'TLOG_SUBMISSION_BUSY', message: 'submission is in progress; retry with the same bytes' },
      { state: 'pending', retryable: true, retryWithSameBytes: true },
    ],
    [
      503,
      { error: 'TLOG_SUBMISSION_INDETERMINATE', message: 'retry with the same idempotency key and exact entry bytes' },
      { state: 'indeterminate', retryable: true, retryWithSameBytes: true },
    ],
    [
      422,
      { error: 'TLOG_PREPARATION_MISMATCH', message: 'completed entry differs from preparation' },
      { state: 'rejected', retryable: false, retryWithSameBytes: false },
    ],
  ])('preserves structured prepared-event submission error semantics for HTTP %i', async (status, body, expected) => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;
    const result = client(fetchMock).submitPreparedEvent('agent.example.com', new Uint8Array([1]), 'rotation-1');
    await expect(result).rejects.toMatchObject({
      name: 'PreparedEventSubmissionError',
      code: body.error,
      httpStatus: status,
      message: body.message,
      ...expected,
    });
    await expect(result).rejects.toBeInstanceOf(PreparedEventSubmissionError);
  });

  it('submits and reissues Live proof with the request ID as the idempotency key', async () => {
    const challengeMessage = await liveChallengeMessage('challenge-2');
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe('live-1');
      if (url.endsWith('/proof/reissue')) {
        expect(JSON.parse(String(init?.body))).toEqual({ request_id: 'live-1' });
        return new Response(JSON.stringify({
          request_id: 'live-1', agent_id: 'agent-live-1', status: 'challenge_pending',
          challenge: 'challenge-2', challenge_message: challengeMessage,
        }), { status: 202 });
      }
      expect(url).toBe('https://registry.example/api/v1/agent/live.example/proof');
      expect(JSON.parse(String(init?.body))).toEqual({
        request_id: 'live-1', challenge: 'challenge-1', public_key: TEST_JWK, signature: 'AQID',
      });
      return new Response(JSON.stringify({
        request_id: 'live-1', agent_id: 'agent-live-1', status: 'provider_deferred',
      }), { status: 202 });
    }) as unknown as typeof fetch;
    const registry = client(fetchMock);

    await expect(registry.submitLiveProof('live.example', {
      requestId: 'live-1', challenge: 'challenge-1', publicKeyJwk: TEST_JWK,
      signature: new Uint8Array([1, 2, 3]),
    })).resolves.toMatchObject({ requestId: 'live-1', agentId: 'agent-live-1', status: 'provider_deferred' });
    await expect(registry.reissueLiveProof('live.example', 'live-1', TEST_JWK)).resolves.toMatchObject({
      requestId: 'live-1', challenge: 'challenge-2', challengeMessage,
      domain: 'live.example', challengeTranscript: { nonce: 'challenge-2', fqdn: 'live.example' },
    });
  });

  it('rejects a reissued Live proof challenge bound to a different public key', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      request_id: 'live-1', agent_id: 'agent-live-1', status: 'challenge_pending',
      challenge: 'challenge-2',
      challenge_message: await liveChallengeMessage('challenge-2', 'agent-live-1', 'live.example', OTHER_TEST_JWK),
    }), { status: 202 })) as unknown as typeof fetch;

    await expect(client(fetchMock).reissueLiveProof('live.example', 'live-1', TEST_JWK))
      .rejects.toThrow('public key binding mismatch');
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([
    ['Live registration', (registry: RegistryClient, publicKeyJwk: DnsIdJWK) => registry.registerLiveAgent({ publicKeyJwk }, 'live-1')],
    ['Live proof reissue', (registry: RegistryClient, publicKeyJwk: DnsIdJWK) => registry.reissueLiveProof('live.example', 'live-1', publicKeyJwk)],
  ])('snapshots the public-key binding before network I/O for %s', async (_label, call) => {
    const challengeMessage = await liveChallengeMessage('challenge-2');
    let requestStarted!: () => void;
    let sendResponse!: () => void;
    const started = new Promise<void>(resolve => { requestStarted = resolve; });
    const responseReady = new Promise<void>(resolve => { sendResponse = resolve; });
    const fetchMock = vi.fn(async () => {
      requestStarted();
      await responseReady;
      return new Response(JSON.stringify({
        request_id: 'live-1', agent_id: 'agent-live-1', status: 'challenge_pending',
        challenge: 'challenge-2', challenge_message: challengeMessage,
      }), { status: 202 });
    }) as unknown as typeof fetch;
    const mutableKey = { ...TEST_JWK };

    const result = call(client(fetchMock), mutableKey);
    await started;
    mutableKey.x = OTHER_TEST_JWK.x;
    sendResponse();

    await expect(result).resolves.toMatchObject({
      challengeTranscript: { keyId: await jwkThumbprint(TEST_JWK) },
    });
  });

  it('applies token, custom headers, credentials, and idempotency key', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get('Authorization')).toBe('Bearer test-token');
      expect(headers.get('X-Test')).toBe('yes');
      expect(init?.credentials).toBe('include');
      if (url.endsWith('/status')) {
        return new Response(JSON.stringify({ id: 'agent-1', domain: 'agent.example.com', status: 'PENDING', managed: 'self' }));
      }
      expect(headers.get('Idempotency-Key')).toBe('idem-1');
      expect(JSON.parse(String(init?.body))).toMatchObject({
        domain: 'agent.example.com',
        managed: false,
        environment: 'production',
      });
      return new Response(JSON.stringify({ domain: 'agent.example.com', status: 'PENDING' }), { status: 201 });
    }) as unknown as typeof fetch;

    const registry = new RegistryClient({
      baseUrl: 'https://registry.example/',
      token: 'test-token',
      headers: { 'X-Test': 'yes' },
      credentials: 'include',
      fetch: fetchMock,
    });

    await expect(registry.registerSelfManagedAgent({
      domain: 'agent.example.com',
      environment: 'production',
      idempotencyKey: 'idem-1',
    }))
      .resolves.toMatchObject({ domain: 'agent.example.com', registryStatus: 'PENDING', publicationAuthority: 'client' });
  });

  it.each([
    undefined,
    'sandbox',
  ] as const)('rejects %s self-managed registration before making a request', async (environment) => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const registry = new RegistryClient({ fetch: fetchMock });
    await expect(registry.registerSelfManagedAgent({
      domain: 'agent.example.com',
      environment,
      idempotencyKey: 'registration-1',
    })).rejects.toThrow('domain must not be supplied for managed registrations');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [{ domain: 'agent.example.com', zoneId: 'zone-1', environment: 'production' as const }, 'domain and zoneId'],
    [{ domain: 'agent.example.com', managed: true, environment: 'production' as const }, 'domain must not be supplied'],
    [{ domain: 'agent.example.com', environment: 'sandbox' as const }, 'domain must not be supplied'],
    [{ environment: 'production' as const }, 'requires a domain'],
    [{ managed: false, environment: 'production' as const }, 'requires a domain'],
    [{ tier: 'live' as never }, 'use registerLiveAgent'],
    [{ environment: 'staging' as never }, 'must be "sandbox" or "production"'],
    [{ environment: 'development' as never }, 'must be "sandbox" or "production"'],
  ])('rejects contradictory generic registration %#', async (input, message) => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const registry = new RegistryClient({ fetch: fetchMock });
    await expect(registry.registerAgent(input as never)).rejects.toThrow(message);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('treats sandbox and zone registrations as managed even when managed is false', async () => {
    const requests: Record<string, unknown>[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/status')) {
        return new Response(JSON.stringify({ domain: 'assigned.sandbox.dnsid.dev', status: 'PENDING', managed: 'dnsid' }));
      }
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(JSON.stringify({ domain: 'assigned.sandbox.dnsid.dev', status: 'PENDING' }), { status: 201 });
    }) as unknown as typeof fetch;
    const registry = client(fetchMock);

    await expect(registry.registerAgent({ managed: false, idempotencyKey: 'registration-1' })).resolves.toMatchObject({ publicationAuthority: 'registry' });
    await expect(registry.registerAgent({ managed: false, zoneId: 'zone-1', environment: 'production', idempotencyKey: 'registration-2' }))
      .resolves.toMatchObject({ publicationAuthority: 'registry' });
    expect(requests).toEqual([
      expect.objectContaining({ environment: 'sandbox', managed: true }),
      expect.objectContaining({ environment: 'production', managed: true, zone_id: 'zone-1' }),
    ]);
  });

  it('rejects private registration key material before making a request', async () => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    const registry = new RegistryClient({ fetch: fetchMock });
    await expect(registry.registerManagedAgent({
      publicKeyJwk: { ...TEST_JWK, d: 'private' } as DnsIdJWK,
      idempotencyKey: 'registration-1',
    })).rejects.toThrow('private JWK member d');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['ordinary registration', (registry: RegistryClient) => registry.registerManagedAgent({ publicKeyJwk: JWKS_SHAPED_JWK, idempotencyKey: 'registration-1' })],
    ['managed Live registration', (registry: RegistryClient) => registry.registerLiveAgent({ publicKeyJwk: JWKS_SHAPED_JWK }, 'live-1')],
    ['managed Live proof', (registry: RegistryClient) => registry.submitLiveProof('live.example', {
      requestId: 'live-1', challenge: 'challenge-1', publicKeyJwk: JWKS_SHAPED_JWK, signature: 'signature',
    })],
    ['managed Live proof reissue', (registry: RegistryClient) => registry.reissueLiveProof('live.example', 'live-1', JWKS_SHAPED_JWK)],
    ['key rotation preparation', (registry: RegistryClient) => registry.prepareKeyRotation('agent.example', {
      previousKeyId: 'old-key', publicKey: JWKS_SHAPED_JWK,
    }, 'rotation-1')],
  ])('rejects a JWKS-shaped key with nested private material for %s before fetch', async (_label, call) => {
    const fetchMock = vi.fn() as unknown as typeof fetch;
    await expect(call(new RegistryClient({ fetch: fetchMock }))).rejects.toThrow('single JWK, not a JWKS');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ['managed', (registry: RegistryClient) => registry.registerManagedAgent({ publicKeyJwk: TEST_JWK, idempotencyKey: 'registration-1' })],
    ['zone-managed', (registry: RegistryClient) => registry.registerInZone({ zoneId: 'zone-1', idempotencyKey: 'registration-1' })],
  ])('defaults %s registration to sandbox', async (_label, register) => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/status')) {
        return new Response(JSON.stringify({ domain: 'assigned.sandbox.dnsid.dev', status: 'PENDING', managed: 'dnsid' }));
      }
      expect(JSON.parse(String(init?.body))).toMatchObject({ environment: 'sandbox', managed: true });
      return new Response(JSON.stringify({ domain: 'assigned.sandbox.dnsid.dev', status: 'PENDING' }), { status: 201 });
    }) as unknown as typeof fetch;
    await expect(register(client(fetchMock))).resolves.toMatchObject({ publicationAuthority: 'registry' });
  });

  it('keeps registry and protocol status separate', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      domain: 'agent.example',
      status: 'ready_for_publication',
      managed: 'dnsid',
      dns_published: true,
      protocolStatus: {
        state: 'ACTIVE',
        lastTransitionAt: '2026-05-15T00:00:00.000Z',
      },
    }))) as unknown as typeof fetch;

    const registration = await client(fetchMock).getRegistration('agent.example');

    expect(registration).toMatchObject({
      id: 'agent-1',
      domain: 'agent.example',
      publicationAuthority: 'registry',
      registryStatus: 'ready_for_publication',
      dnsPublished: true,
      protocolStatus: { state: 'ACTIVE' },
    });
    expect(registration?.protocolStatus?.lastTransitionAt.toISOString()).toBe('2026-05-15T00:00:00.000Z');
  });

  it('exposes the registry publication configuration as typed SDK values', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      domain: 'agent.example',
      status: 'PENDING',
      managed: 'self',
      publication_config: {
        publish_profile: 'dnsid-draft-01',
        governance_id: 'example',
        ku_url: 'https://agent.example/jwks.json',
        ek_url: 'https://example/entity.jwks',
        log_ref: 'c2sp-tlog:custom',
        status_url: 'https://registry.example/status/agent.example',
        capabilities_url: 'https://agent.example/capabilities.json',
        max_key_age: '30d',
      },
    }))) as unknown as typeof fetch;

    await expect(client(fetchMock).getRegistration('agent.example')).resolves.toMatchObject({
      publicationConfig: {
        publishProfile: 'dnsid-draft-01',
        governanceId: 'example',
        kuUrl: 'https://agent.example/jwks.json',
        ekUrl: 'https://example/entity.jwks',
        logRef: 'c2sp-tlog:custom',
        statusUrl: 'https://registry.example/status/agent.example',
        capabilitiesUrl: 'https://agent.example/capabilities.json',
        maxKeyAge: '30d',
      },
    });
  });

  it.each(['REVOKED', 'RETIRED'])('stops status and publication polling when an agent is %s', async terminalStatus => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      domain: 'agent.example', status: terminalStatus, managed: 'dnsid', dns_published: false,
    }))) as unknown as typeof fetch;
    const registry = client(fetchMock);

    await expect(registry.waitForStatus('agent.example', status => status.registryStatus === terminalStatus))
      .rejects.toThrow(`terminal status ${terminalStatus}`);
    await expect(awaitRegistryManagedPublication({
      domain: 'agent.example', registryClient: registry,
      identityManager: { verifyPublicationEvidence: vi.fn() },
    })).rejects.toThrow(`publication failed with status ${terminalStatus}`);
  });

  it('does not fabricate protocol status from failed registry state', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      status: 'ERROR',
      managed: 'self',
    }))) as unknown as typeof fetch;

    await expect(client(fetchMock).getRegistration('agent.example')).resolves.toMatchObject({
      publicationAuthority: 'client',
      registryStatus: 'ERROR',
      protocolStatus: undefined,
    });
  });

  it('returns undefined when the registry has no agent status', async () => {
    const fetchMock = vi.fn(async () => new Response('not found', { status: 404 })) as unknown as typeof fetch;
    const registry = new RegistryClient({ baseUrl: 'https://registry.example', fetch: fetchMock });

    await expect(registry.getRegistration('agent.example')).resolves.toBeUndefined();
  });
});
