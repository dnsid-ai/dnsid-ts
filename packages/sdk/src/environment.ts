import { DNSSECMode, type DnsidConfig, type IdentityConfig } from '@dnsid-ai/protocol';
import { DEFAULT_REGISTRY_URL } from '@dnsid-ai/registry';

export const dnsidEnvironmentVariables = {
  domain: 'DNSID_DOMAIN',
  governanceId: 'DNSID_GOVERNANCE_ID',
  registryUrl: 'DNSID_REGISTRY_URL',
  statusUrl: 'DNSID_STATUS_URL',
  logRef: 'DNSID_LOG_REF',
  ekUrl: 'DNSID_EK_URL',
  kuUrl: 'DNSID_KU_URL',
  dnsServer: 'DNSID_DNS_SERVER',
  caBundlePath: 'DNSID_CA_BUNDLE',
  dnssecMode: 'DNSID_DNSSEC_MODE',
  publicUrl: 'DNSID_PUBLIC_URL',
  keyStorePath: 'DNSID_KEY_STORE',
  agentPort: 'DNSID_AGENT_PORT',
  agentName: 'DNSID_AGENT_NAME',
} as const;

export type EnvironmentFieldName = keyof typeof dnsidEnvironmentVariables;
type EnvironmentVariableName = (typeof dnsidEnvironmentVariables)[EnvironmentFieldName];
type EnvironmentSource = Record<string, string | undefined>;

interface EnvironmentField<T> {
  variable: EnvironmentVariableName;
  parse(value: string, variable: EnvironmentVariableName): T;
}

const environmentSchema = {
  domain: stringField(dnsidEnvironmentVariables.domain),
  governanceId: stringField(dnsidEnvironmentVariables.governanceId),
  registryUrl: stringField(dnsidEnvironmentVariables.registryUrl),
  statusUrl: stringField(dnsidEnvironmentVariables.statusUrl),
  logRef: stringField(dnsidEnvironmentVariables.logRef),
  ekUrl: stringField(dnsidEnvironmentVariables.ekUrl),
  kuUrl: stringField(dnsidEnvironmentVariables.kuUrl),
  dnsServer: stringField(dnsidEnvironmentVariables.dnsServer),
  caBundlePath: stringField(dnsidEnvironmentVariables.caBundlePath),
  dnssecMode: dnssecModeField(dnsidEnvironmentVariables.dnssecMode),
  publicUrl: stringField(dnsidEnvironmentVariables.publicUrl),
  keyStorePath: stringField(dnsidEnvironmentVariables.keyStorePath),
  agentPort: positiveIntField(dnsidEnvironmentVariables.agentPort),
  agentName: stringField(dnsidEnvironmentVariables.agentName),
} satisfies Record<EnvironmentFieldName, EnvironmentField<unknown>>;

type EnvironmentValue<K extends EnvironmentFieldName> =
  typeof environmentSchema[K] extends EnvironmentField<infer T> ? T : never;

export type DnsidEnvironment = {
  [K in EnvironmentFieldName]?: EnvironmentValue<K>;
};

type ConfigForEnvironment<RequiredFields extends EnvironmentFieldName> = DnsidConfig & {
  identity: IdentityConfig & Required<Pick<IdentityConfig, Extract<RequiredFields, keyof IdentityConfig>>>;
};

interface EnvironmentConfigResultBase<RequiredFields extends EnvironmentFieldName = never> {
  /** Core configuration: `identity` publication fields, `verification.dnssecMode`, and `transport` from the environment. */
  config: ConfigForEnvironment<RequiredFields>;
  /** Base URL of the DNSid registry for control-plane workflows. Defaults to `https://api.dnsid.ai`. Not core config. */
  registryUrl: string;
  /** Optional public base URL for the agent, e.g. https://alice.example.com. */
  publicUrl?: string;
  /** Optional local key-store path for LocalKeyProvider. */
  keyStorePath?: string;
  /** Optional example/server display name. */
  agentName?: string;
  /** Optional example/server port. */
  agentPort?: number;
}

export type EnvironmentConfigResult<RequiredFields extends EnvironmentFieldName = never> =
  EnvironmentConfigResultBase<RequiredFields> &
  Required<
    Pick<EnvironmentConfigResultBase<RequiredFields>, Extract<RequiredFields, keyof EnvironmentConfigResultBase<RequiredFields>>>
  >;

export interface ConfigFromEnvironmentOptions<RequiredFields extends EnvironmentFieldName = never> {
  require?: readonly RequiredFields[];
}

/**
 * Explicit loader mapping DNSID_* environment variables to a {@link DnsidConfig} plus
 * registry/example settings. Constructors never read the environment themselves.
 */
export function configFromEnvironment<const RequiredFields extends EnvironmentFieldName = never>(
  options?: ConfigFromEnvironmentOptions<RequiredFields>,
): EnvironmentConfigResult<RequiredFields>;
export function configFromEnvironment<const RequiredFields extends EnvironmentFieldName = never>(
  env: EnvironmentSource | undefined,
  options?: ConfigFromEnvironmentOptions<RequiredFields>,
): EnvironmentConfigResult<RequiredFields>;
export function configFromEnvironment<const RequiredFields extends EnvironmentFieldName = never>(
  envOrOptions: EnvironmentSource | ConfigFromEnvironmentOptions<RequiredFields> | undefined = process.env,
  options: ConfigFromEnvironmentOptions<RequiredFields> = {},
): EnvironmentConfigResult<RequiredFields> {
  const receivedOptions = isConfigFromEnvironmentOptions(envOrOptions);
  const env = receivedOptions ? process.env : (envOrOptions ?? process.env);
  const resolvedOptions = receivedOptions ? envOrOptions : options;
  const parsed = parseEnvironment(env);
  requireFields(parsed, ['domain', 'governanceId', ...(resolvedOptions.require ?? [])]);

  const registryUrl = parsed.registryUrl ?? DEFAULT_REGISTRY_URL;
  const statusUrl = parsed.statusUrl ?? protocolStatusUrl(registryUrl, parsed.domain);

  const config: DnsidConfig = {
    identity: defined({
      domain: parsed.domain,
      governanceId: parsed.governanceId,
      logRef: parsed.logRef ?? 'noop:0',
      statusUrl,
      ekUrl: parsed.ekUrl,
      kuUrl: parsed.kuUrl,
    }),
    verification: defined({ dnssecMode: parsed.dnssecMode }),
    transport: defined({ dnsServer: parsed.dnsServer, caBundlePath: parsed.caBundlePath }),
  };
  return {
    config,
    registryUrl,
    publicUrl: parsed.publicUrl,
    keyStorePath: parsed.keyStorePath,
    agentName: parsed.agentName,
    agentPort: parsed.agentPort,
  } as EnvironmentConfigResult<RequiredFields>;
}

function defined<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T;
}

function isConfigFromEnvironmentOptions(
  value: EnvironmentSource | ConfigFromEnvironmentOptions<EnvironmentFieldName> | undefined,
): value is ConfigFromEnvironmentOptions<EnvironmentFieldName> {
  if (value === undefined) return false;
  const keys = Object.keys(value);
  if (keys.length === 0) return true;
  return keys.every(key => key === 'require') && Array.isArray((value as ConfigFromEnvironmentOptions).require);
}

function parseEnvironment(env: EnvironmentSource): DnsidEnvironment {
  const parsed: DnsidEnvironment = {};
  for (const fieldName of Object.keys(environmentSchema) as EnvironmentFieldName[]) {
    const value = readEnvironmentField(env, fieldName);
    if (value !== undefined) parsed[fieldName] = value as never;
  }
  return parsed;
}

function readEnvironmentField<K extends EnvironmentFieldName>(
  env: EnvironmentSource,
  fieldName: K,
): EnvironmentValue<K> | undefined {
  const field = environmentSchema[fieldName];
  const raw = env[field.variable];
  if (raw === undefined || raw === '') return undefined;
  return field.parse(raw, field.variable) as EnvironmentValue<K>;
}

function requireFields<T extends DnsidEnvironment>(
  parsed: T,
  fields: readonly EnvironmentFieldName[],
): asserts parsed is T & Required<Pick<DnsidEnvironment, typeof fields[number]>> {
  for (const field of fields) {
    if (parsed[field] === undefined) throw new Error(`${environmentSchema[field].variable} is required`);
  }
}

function stringField(variable: EnvironmentVariableName): EnvironmentField<string> {
  return { variable, parse: value => value };
}

function positiveIntField(variable: EnvironmentVariableName): EnvironmentField<number> {
  return {
    variable,
    parse(value, name) {
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`${name} must be a positive integer`);
      }
      return parsed;
    },
  };
}

function dnssecModeField(variable: EnvironmentVariableName): EnvironmentField<DNSSECMode> {
  return {
    variable,
    parse(value, name) {
      if (!Object.values(DNSSECMode).includes(value as DNSSECMode)) {
        throw new Error(`invalid ${name} "${value}"; expected one of: ${Object.values(DNSSECMode).join(', ')}`);
      }
      return value as DNSSECMode;
    },
  };
}

function protocolStatusUrl(registryUrl: string, domain: string): string {
  return `${registryUrl.replace(/\/$/, '')}/v1/status/${encodeURIComponent(domain)}`;
}
