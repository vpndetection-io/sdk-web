# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff.

## 1.1.1 - 2026-11-11

### Fixes

- Re-pin the spec's 2026.11.11 rebuild: plainer words on lookups without a key ([`8a879f6`](https://github.com/vpndetection-io/sdk-web/commit/8a879f6a2c0621ae9fa5229642baa3008725df14))
- Name the Unlimited tier and its terms, and re-pin the spec ([`c07954a`](https://github.com/vpndetection-io/sdk-web/commit/c07954a9b49f30fef9f3b6cc3d689e274da44b30))

## 1.1.0 - 2026-11-11

### Features

- Re-pin the spec to 2026.11.11: a lookup without a key answers more ([`5e9e697`](https://github.com/vpndetection-io/sdk-web/commit/5e9e697510866323355301fe436579331306d403))

## 1.0.0 - 2026-11-06

### Features

- Look up an address, or many in one call, from a browser: `lookup` and `lookupBatch`, with bogons answered locally, retries, per-attempt timeouts and the errors every VPNDetection library raises ([`15ac1bd`](https://github.com/vpndetection-io/sdk-web/commit/15ac1bd0baa5ecd2729e708ade9d633edf88c04c))
- Ask about the address the browser calls from with `myIp`, and what a key may spend with `myEntitlement` ([`15ac1bd`](https://github.com/vpndetection-io/sdk-web/commit/15ac1bd0baa5ecd2729e708ade9d633edf88c04c))
- Cache answers per client, concurrent misses sharing one request, with an optional `store` that keeps them across a page reload or an extension's worker restart ([`15ac1bd`](https://github.com/vpndetection-io/sdk-web/commit/15ac1bd0baa5ecd2729e708ade9d633edf88c04c))
- Sign a person in with the OAuth authorization code flow: `authorizationUrl`, `exchangeAuthorizationCode`, `exchangeRefreshToken`, `revoke`, `metadata`, and PKCE from Web Crypto with `createPkce` and `pkceChallenge` ([`15ac1bd`](https://github.com/vpndetection-io/sdk-web/commit/15ac1bd0baa5ecd2729e708ade9d633edf88c04c))
- ES modules with types and nothing of Node.js, from npm or from jsDelivr in a module script ([`15ac1bd`](https://github.com/vpndetection-io/sdk-web/commit/15ac1bd0baa5ecd2729e708ade9d633edf88c04c))
