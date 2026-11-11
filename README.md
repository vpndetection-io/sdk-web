# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="28"/>](https://vpndetection.io/) VPNDetection Web Client Library

[![npm](https://img.shields.io/npm/v/vpndetection-web.svg)](https://www.npmjs.com/package/vpndetection-web)
[![license](https://img.shields.io/npm/l/vpndetection-web.svg)](LICENSE)

The official browser client library for the [VPNDetection](https://vpndetection.io) API, for a page's own scripts and for browser extensions.

It tells you whether an IP address is a VPN, residential proxy, Tor node, relay or hosting server.

**An API key in a web page is public.** Anyone who opens the page can read it from the page's source or its network requests, and spend your allowance with it. In a page, use no key, or call the API from your own server and hand the page its answer. A key belongs only where the person it belongs to is the only one who can read it: their own browser extension, or an internal tool.

## Getting Started

```bash
npm install vpndetection-web
```

Or, with no build step, import it from jsDelivr in a module script:

```html
<script type="module">
    import { VPNDetection } from 'https://cdn.jsdelivr.net/npm/vpndetection-web@1/+esm';

    const me = await new VPNDetection().myIp();
    console.log(me.isVpn);
</script>
```

It runs in Chrome and Edge 109, Firefox 115 ESR and Safari 16.4 or newer. TypeScript types are included.

## Usage

**No API key needed to start.** Unlimited, the free plan, answers `ip`, `is_vpn`, Tor and relay detection, `location` and `asn`, with no daily or monthly cap, with a key or without one. In a page the address calling is the visitor's, so `myIp` tells you about the visitor:

```js
import { VPNDetection } from 'vpndetection-web';

const client = new VPNDetection();

const me = await client.myIp();
console.log(me.isVpn);       // is this visitor on a VPN?

const result = await client.lookup('45.83.91.1');
console.log(result.isVpn);              // true
console.log(result.location?.country);  // the ISO 3166 country code
console.log(result.asn?.name);          // who runs the announcing network
```

### With an API key

Where the key stays private (see above), every paid plan answers every field: `is_hosting`, `is_cdn` and the four proxy flags as well, and the provider, confidence and last-seen detail behind each flag. The plans differ only in how many lookups they include, and a free account tries every field, 100 lookups a day. Create a key in the [console](https://app.vpndetection.io), then pass it in:

```js
const client = new VPNDetection({ apiKey: 'your-api-key' });

const result = await client.lookup('45.83.91.1');
console.log(result.isVpn);              // true
console.log(result.isHosting);          // on a paid plan
console.log(result.vpn?.provider);      // on a paid plan
```

An extension can sign its user in rather than ask them to paste a key: see Sign in with OAuth below.

### Your own address

```js
const result = await client.myIp();
console.log(result.ip);   // the address we saw this call come from: in a page, the visitor's
```

It is never cached, since which address the browser is calling from is the question, and a laptop moves between networks.

### Your plan and usage

```js
const ent = await client.myEntitlement();
console.log(ent.plan.key);          // max
console.log(ent.usage.requests);    // 580
console.log(ent.usage.window_end);  // when the allowance resets
```

Usage counts against the anniversary of your subscription on a paid plan, not the calendar month and not the billing period, and against the UTC day on the free plan; it is the same number a lookup is gated on. `hard_limit` is null on an uncapped plan, which is not the same as zero. It needs a key, so it belongs where a key does.

### Batch lookup

Look up as many addresses as you like in one call. Bogons and cached answers are handled locally, and the rest go to the batch endpoint in chunks of up to 1000, in parallel. The batch endpoint needs a paid plan:

```js
const results = await client.lookupBatch(['45.83.91.1', '8.8.8.8', '1.1.1.1']);

for (const [ip, result] of results) {
    if (result instanceof Error) {
        console.log(`${ip}: ${result.message}`);
        continue;
    }
    console.log(`${ip}: ${result.isVpn}`);
}
```

Results are keyed by address, in the order you first listed each one, so duplicates in your list collapse into a single entry and one address failing never loses the rest: it carries its error as its value, with the status the API would have given that address on its own.

How many chunks are in flight at once, how many times a failed chunk is retried, and how long each request may take are configurable per call:

```js
const results = await client.lookupBatch(manyIps, { concurrency: 4, retries: 4, timeoutMs: 10_000 });
```

### Caching

Answers are cached in memory by default, so repeat lookups of the same address are free, and lookups of one address made at the same moment share a single request:

```js
const client = new VPNDetection();

const result = await client.lookup('45.83.91.1');
console.log(result.isVpn);   // true, API request

const result2 = await client.lookup('45.83.91.1');
console.log(result2.isVpn);  // true, no API request, result was cached
```

You can change the default cache variables (max size, TTL, etc) on initialization, or even disable it:

```js
const client = new VPNDetection({ cache: { max: 50_000, ttlMs: 6 * 60 * 60 * 1000 } });
const clientNoCache = new VPNDetection({ cache: false });
```

### Keeping answers across a reload

The in-memory cache lasts as long as the client, so a page reload starts with an empty one, and so does an extension's service worker, which the browser stops once it sits idle. Give the cache a `store` and answers outlive the client: it is read when the in-memory cache misses, before the network, and written after each answer the API serves. In a page, `sessionStorage` keeps them for the tab:

```js
const store = {
    get(key) {
        const saved = JSON.parse(sessionStorage.getItem(`vpndetection:${key}`) ?? 'null');
        return saved !== null && saved.expires > Date.now() ? saved.result : undefined;
    },
    set(key, result, ttlMs) {
        const saved = { result: result, expires: Date.now() + ttlMs };
        sessionStorage.setItem(`vpndetection:${key}`, JSON.stringify(saved));
    },
};

const client = new VPNDetection({ cache: { store: store } });
```

In an extension's service worker, `chrome.storage.session` does the same. A store's methods may return promises, as these do:

```js
const store = {
    async get(key) {
        const saved = (await chrome.storage.session.get(key))[key];
        return saved !== undefined && saved.expires > Date.now() ? saved.result : undefined;
    },
    async set(key, result, ttlMs) {
        await chrome.storage.session.set({ [key]: { result: result, expires: Date.now() + ttlMs } });
    },
};

const client = new VPNDetection({ cache: { store: store } });
```

`set` is told how long the answer stays fresh, and dropping it after that is the store's job. Each `key` carries a hash of the client's API key and base URL beside the address, so clients holding different keys can share one store without reading each other's answers. Bogons, errors, `myIp` and `myEntitlement` are never stored, and a store that fails costs a request, never an answer: a `get` that throws reads as a miss, and a `set` that throws is ignored.

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```js
const result = await client.lookup('192.168.1.1');
result.isBogon;   // true, this answer was computed rather than served
result.isVpn;     // false
```

The check is available on the client, which is handy when your inputs are addresses anyway:

```js
client.isBogon('10.0.0.1');    // true
client.isBogon('8.8.8.8');     // false
```

It is also importable on its own, if you want it without a client:

```js
import { isBogon } from 'vpndetection-web';

isBogon('10.0.0.1');    // true
```

### Errors

Failures throw a `VPNDetectionError` carrying a `kind` and a `retryable` flag:

```js
import { VPNDetectionError } from 'vpndetection-web';

try {
    await client.lookup('1.1.1.1');
} catch (err) {
    if (err instanceof VPNDetectionError) {
        console.error(err.kind, err.retryable);
    }
}
```

`kind` is one of `bad_request`, `unauthorized`, `forbidden`, `rate_limited`, `quota_exceeded`, `server_error` or `network`.

Note that `rate_limited` and `quota_exceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

A request the browser never got an answer to is a retryable `network` error carrying what the browser said: offline, blocked by an extension, or refused by the page's Content-Security-Policy.

### Timeouts

A request that hasn't finished after 30 seconds is abandoned and surfaces as a retryable `network` error. The limit applies to each attempt, so a call that gets retried can take longer in total. Set it for the client, or for a single lookup:

```js
const client = new VPNDetection({ timeoutMs: 10_000 });

const result = await client.lookup('45.83.91.1', { timeoutMs: 2000 });
```

### Sign in with OAuth (authorization code)

An app or an extension that can take a browser redirect signs the person in there, with a PKCE pair made for that one sign-in:

```js
const client = new VPNDetection();
const redirectUri = 'https://your-app.example/callback';
const pkce = await client.oauth.createPkce();

const url = client.oauth.authorizationUrl('your-client-id', redirectUri, pkce.challenge, {
    scope: 'apikeys.use', state: 'your-state',
});
// Send the browser to url. Its redirect to redirectUri carries code and state.
const token = await client.oauth.exchangeAuthorizationCode('your-client-id', code, pkce.verifier, redirectUri);
```

Check that `state` came back as you sent it before you exchange `code`, which works once. The client ID can also be the https URL of a client metadata document your app serves, and such an app is never handed a key, so `token.apikey` stays absent.

`createPkce` and `pkceChallenge` return promises, as Web Crypto does, and need a secure context: a page served over https or from localhost, or an extension. `exchangeRefreshToken` trades the refresh token for a new pair, and `revoke` with it signs the person out. Client IDs are issued on request from support@vpndetection.io.

### Browser support

The library is ES2022 and needs only what a browser has, `fetch` and, for PKCE, Web Crypto, so it runs in Chrome and Edge 109, Firefox 115 ESR and Safari 16.4 or newer: in a page, a web worker, or an extension's service worker. Every endpoint it calls answers CORS for any origin, so a page needs nothing from your server. A page whose Content-Security-Policy restricts `connect-src` must allow `https://api.vpndetection.io`. For Node.js, use [vpndetection](https://www.npmjs.com/package/vpndetection) instead.

### Absent is not false

The Unlimited tier leaves out `isHosting`, `isCdn` and the four proxy flags, and of the detail behind each flag it answers only Tor's and relay's; a free-plan key's answer carries `trialExpired`, true once its daily trial is spent. A field your key does not include is `undefined`, which means "not in your plan" rather than "checked, and no".

```js
result.isHosting ?? false        // when you only want the flag
result.isHosting === undefined   // on the Unlimited tier: not in your plan
result.trialExpired === true     // a free-plan key's daily trial is spent
```

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="64"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
