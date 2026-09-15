/** Read the independently supplied C2SP policy trust anchor for the local testnet. */
export function requiredTestnetLogPolicyUrl(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): string {
  const policyUrl = environment.DNSID_LOG_POLICY_URL?.trim();
  if (!policyUrl) throw new Error('DNSID_LOG_POLICY_URL is required; run with `dnsid testnet run`');
  return policyUrl;
}
