export function publicationConfig(domain: string) {
  return {
    publish_profile: 'dnsid-draft-01',
    governance_id: 'example.com',
    ku_url: `https://${domain}/jwks.json`,
    ek_url: 'https://example.com/entity.jwks',
    log_ref: 'microledger:abc123',
    status_url: `https://${domain}/status`,
  };
}

export function creation(domain: string) {
  return { id: 'agent-1', domain, publication_config: publicationConfig(domain) };
}
