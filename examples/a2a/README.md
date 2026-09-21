# DNSid A2A example

Runs two A2A agents, Alice and Bob, on the local DNSid testnet. Each agent gets a DNSid identity from `dnsid testnet run` and signs/verifies A2A requests with RFC 9421 HTTP Message Signatures.

## Run

Install the `dnsid` CLI ([installation guide](https://docs.dnsid.ai/cli-installation)) and make sure Docker is running. The CLI manages the testnet directly. By default it pulls `ghcr.io/identity-digital/dnsid-testnet-registry:latest`.

If the CLI is not the `dnsid` on your `PATH`, set
`DNSID_CLI=/path/to/dnsid`. To override the container image, set
`DNSID_TESTNET_IMAGE` before `testnet up`. If a testnet is already running with
another image, stop or hard-reset it before starting the replacement.

Prepare both managed identities and submit their operationally countersigned
C2SP ISSUANCE entries before starting either agent:

```sh
CLI="${DNSID_CLI:-dnsid}"

"$CLI" testnet up
"$CLI" testnet agent ensure bob --upstream http://localhost:3002 \
  -- "$CLI" log issue --domain bob.dev.dnsid.test
"$CLI" testnet agent ensure alice --upstream http://localhost:3001 \
  -- "$CLI" log issue --domain alice.dev.dnsid.test
```

`dnsid log issue` is idempotent, so this preparation is safe to rerun for
existing identities.

```sh
# Terminal 1 — start Bob and leave it running
npm -w examples/a2a run bob

# Terminal 2 — start Alice, send one message to Bob, then exit
npm -w examples/a2a run alice
```

`dnsid testnet run` starts the local testnet if needed, creates/reuses agent identity files under `~/.dnsid-testnet`, registers each local upstream, and injects the DNS/TLS environment used by the TypeScript SDK. The example requires and consumes the independently trusted `DNSID_LOG_POLICY_URL` value supplied by that environment, preserving non-default testnet ports, rather than discovering trust from an identity record's log reference. Production applications must keep official or pinned policies independently configured in the same way.

The CLI also owns the testnet lifecycle and state:

```sh
dnsid testnet up
dnsid testnet agent list
dnsid testnet env alice
dnsid testnet down
dnsid testnet reset --hard
```

Expected Alice output includes:

```text
verified: alice.dev.dnsid.test -> bob.dev.dnsid.test
reply: "[from: bob.dev.dnsid.test; verified sender: alice.dev.dnsid.test] hello from alice.dev.dnsid.test"
```

Bob is reachable at `https://bob.dev.dnsid.test` through the testnet proxy; no peer localhost URL setup is needed.

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
still sends the same request to `bob.dev.dnsid.test`, demonstrating that all
three implementations use the same A2A wire format.
