# Local Key Provider Example

A simple example to demonstrate some usage of the KeyProvider interface, specifically LocalKeyProvider.

The example loads a local key store (`./keys.json`) if it exists, otherwise creates it and generates a key. 

Also demonstrates generating a new `pending` key and then activates it, demoting the `retained` keys to show key rotation. 

Creates a [JOSE Profile](https://datatracker.ietf.org/wg/jose/about/) and creates/signs a JWT using the provided [dnsid-jose](../../packages/jose/README.md) package.


## Run Example:

From the root directory:

```sh
npm install
npm run start -w @dnsid-ai/example-local-key-provider
```

Note: The key file is written to `./keys.json`. Delete that file to reset the example.
