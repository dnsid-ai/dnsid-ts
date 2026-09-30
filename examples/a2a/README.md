# DNSid A2A example

Runs two A2A agents, Alice and Bob, on the local DNSid testnet. Each agent gets a DNSid identity from `dnsid local run` and signs/verifies A2A requests with RFC 9421 HTTP Message Signatures.

## Run

Install the `dnsid` CLI ([installation guide](https://docs.dnsid.ai/cli-installation)) and make sure Docker is running. The CLI owns the local testnet.

If the CLI is not the `dnsid` on your `PATH`, set
`DNSID_CLI=/path/to/dnsid`.

Prepare both managed identities and submit their operationally countersigned
C2SP ISSUANCE entries before starting either agent:

```sh
CLI="${DNSID_CLI:-dnsid}"

"$CLI" local up --zone test
"$CLI" local agent ensure bob --upstream http://localhost:3002 \
  --cu https://bob.test/.well-known/agent-card.json -- \
  "$CLI" log issue --domain bob.test
"$CLI" local agent ensure alice --upstream http://localhost:3001 \
  --cu https://alice.test/.well-known/agent-card.json -- \
  "$CLI" log issue --domain alice.test
```

`dnsid log issue` is idempotent, so this preparation is safe to rerun for
existing identities.

```sh
# Terminal 1 — start Bob and leave it running
npm -w examples/a2a run bob

# Terminal 2 — start Alice, send one message to Bob, then exit
npm -w examples/a2a run alice
```

`dnsid local run` starts the local testnet if needed, creates/reuses agent identity files under `~/.dnsid-local`, registers each local upstream, and injects the DNS/TLS environment used by the TypeScript SDK. The example builds its identity manager with the SDK's `loadEnvironment` → `mergeLoadedConfig` → `constructIdentityManager` flow: identity from `DNSID_*`, keys from `DNSID_CONFIG_DIR`, and log trust from the independently trusted `DNSID_LOG_POLICY_URL` that `dnsid local run` exports (preserving non-default testnet ports), never from an identity record's log reference. `DNSID_AGENT_PORT`, `DNSID_AGENT_NAME`, and `DNSID_PUBLIC_URL` are deployment settings the example reads itself. Production applications must keep official or pinned policies independently configured in the same way.

The Node factory consumes the loaded transport settings when constructing the
identity manager. The example reuses those same settings for its registry and
outbound A2A clients, rather than reading the cleared `idm.config.transport`.

The CLI also owns the testnet lifecycle and state:

```sh
dnsid local up --zone test
dnsid local agent list
dnsid local env alice
dnsid local down
dnsid local reset --hard
```

Expected Alice output includes:

```text
verified: alice.test -> bob.test
reply: "[from: bob.test; verified sender: alice.test] hello from alice.test"
```

Bob is reachable at `https://bob.test` through the testnet proxy; no peer localhost URL setup is needed.

## Browser protocol inspector

Leave Bob running, then start Alice as an interactive dashboard instead of the
one-shot client:

```sh
npm -w examples/a2a run dashboard
```

Open [http://localhost:3001/demo](http://localhost:3001/demo). The inspector
shows Bob's DNSid verification result, A2A agent card, signed RFC 9421 request,
and Bob's response. Enable **Tamper with the payload after signing** to show
Bob rejecting a request whose body no longer matches its DNSid-bound signature.

The Bob process can instead come from `dnsid-py` or `dnsid-go`. The dashboard
still sends the same request to `bob.test`, demonstrating that all
three implementations use the same A2A wire format.
