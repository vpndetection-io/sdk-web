// The client's own surface, as distinct from the shared conformance corpus in
// conformance.test.mjs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { VPNDetection, VPNDetectionError, isBogon } from '../dist/index.js';

const data = JSON.parse(readFileSync(new URL('../testdata/testdata.json', import.meta.url), 'utf8'));

// Answers slowly enough that concurrent calls overlap, and records the peak
// number in flight. Asserting the PEAK is the only way to tell a real limit
// from an option that was accepted and ignored. A batch arrives as one POST per
// chunk, so it is answered from the addresses in the body.
function concurrencyTrackingFetch(delayMs = 20) {
    const state = { inFlight: 0, peak: 0, calls: 0 };
    const fn = async (input, init) => {
        const body = typeof input === 'string' ? (init?.body ?? '') : await input.text();
        state.calls++;
        state.inFlight++;
        state.peak = Math.max(state.peak, state.inFlight);
        await new Promise((r) => setTimeout(r, delayMs));
        state.inFlight--;
        const results = {};
        for (const ip of JSON.parse(body || '{}').ips ?? []) {
            results[ip] = { ip: ip, is_vpn: false };
        }
        return new Response(JSON.stringify({ results: results, errors: {} }), {
            status: 200, headers: { 'content-type': 'application/json' },
        });
    };
    return { fetch: fn, state: state };
}

// Enough addresses for seven chunks of the batch endpoint's 1000, so a
// concurrency bound has something to bound: one request per chunk, and only the
// chunks overlap.
const addrs = Array.from(
    { length: 6001 },
    (_, i) => `9.${1 + Math.floor(i / 65536)}.${Math.floor(i / 256) % 256}.${i % 256}`,
);

test('isBogon is on the client and agrees with the standalone export', () => {
    const client = new VPNDetection();
    for (const c of data.isBogon) {
        assert.equal(client.isBogon(c.ip), c.expect, `${c.ip} (${c.why})`);
        assert.equal(client.isBogon(c.ip), isBogon(c.ip), `${c.ip}: client and export disagree`);
    }
});

test('batch concurrency is configurable per call', async () => {
    const t = concurrencyTrackingFetch();
    const client = new VPNDetection({ fetch: t.fetch, cache: false });

    await client.lookupBatch(addrs, { concurrency: 3 });

    assert.equal(t.state.calls, 7, 'one request per chunk of 1000');
    assert.ok(t.state.peak <= 3, `peak in flight was ${t.state.peak}, expected at most 3`);
    assert.ok(t.state.peak > 1, 'requests should still overlap');
});

test('a per-call concurrency overrides the client default', async () => {
    const t = concurrencyTrackingFetch();
    // Instance default of 2, raised to 6 for this one batch.
    const client = new VPNDetection({ fetch: t.fetch, cache: false, concurrency: 2 });

    await client.lookupBatch(addrs, { concurrency: 6 });

    assert.ok(t.state.peak > 2, `override ignored: peak was ${t.state.peak}, expected above 2`);
    assert.ok(t.state.peak <= 6, `peak in flight was ${t.state.peak}, expected at most 6`);
});

test('without an override the client concurrency still applies', async () => {
    const t = concurrencyTrackingFetch();
    const client = new VPNDetection({ fetch: t.fetch, cache: false, concurrency: 2 });

    await client.lookupBatch(addrs);

    assert.ok(t.state.peak <= 2, `peak in flight was ${t.state.peak}, expected at most 2`);
});

// p-limit would throw a bare TypeError for these; they are the caller's mistake.
test('a concurrency below 1 or not whole is refused before any request', async () => {
    let calls = 0;
    const client = new VPNDetection({
        fetch: async () => {
            calls++;
            throw new Error('the network must not be reached');
        },
    });
    for (const concurrency of [0, -1, 0.5, 1.5, NaN, '2']) {
        const call = () => client.lookupBatch(['45.83.91.1', '10.0.0.1'], { concurrency: concurrency });
        await assert.rejects(call, (err) => {
            assert.ok(err instanceof VPNDetectionError, `${concurrency}: wrong error type`);
            assert.equal(err.kind, 'bad_request', `${concurrency}`);
            assert.equal(err.retryable, false, `${concurrency}`);
            assert.match(err.message, /concurrency/, `${concurrency}`);
            return true;
        });
        assert.throws(() => new VPNDetection({ concurrency: concurrency }),
            (err) => err instanceof VPNDetectionError && err.kind === 'bad_request', `client ${concurrency}`);
    }
    assert.equal(calls, 0);
    assert.doesNotThrow(() => new VPNDetection({ concurrency: Infinity }));
});

test('retries are configurable per call', async () => {
    let calls = 0;
    const fetchFn = async () => {
        calls++;
        return new Response(JSON.stringify({ error: 'lookup failed' }), {
            status: 500, headers: { 'content-type': 'application/json' },
        });
    };
    const client = new VPNDetection({ fetch: fetchFn, cache: false, retries: 0 });

    await assert.rejects(() => client.lookup('9.9.9.9', { retries: 2 }));
    // 1 initial attempt plus 2 retries, rather than the instance's 0.
    assert.equal(calls, 3);
});

// Two ways a response stalls: nothing arrives, or the headers do and the body
// never finishes. The deadline has to bound the whole call, not just the first.
const STALLS = {
    'no response': () => new Promise(() => {}),
    'a body that never ends': async () => new Response(new ReadableStream({ start() {} }), {
        status: 200, headers: { 'content-type': 'application/json' },
    }),
};

// Every call that takes per-call options, each surfacing its failure as a
// rejection. A batch reports a failed chunk as every address's value instead of
// throwing, so that one rethrows what it was given.
const PER_CALL = {
    'lookup': (c, o) => c.lookup('45.83.91.1', o),
    'myIp': (c, o) => c.myIp(o),
    'myEntitlement': (c, o) => c.myEntitlement(o),
    'lookupBatch': async (c, o) => {
        const answers = [...(await c.lookupBatch(['45.83.91.1', '9.9.9.9'], o)).values()];
        assert.ok(answers.every((a) => a instanceof VPNDetectionError), 'the chunk should fail as a whole');
        throw answers[0];
    },
    'oauth.metadata': (c, o) => c.oauth.metadata(o),
    'oauth.exchangeAuthorizationCode': (c, o) => c.oauth.exchangeAuthorizationCode(
        'your-client-id', 'mo_ac_x', 'v'.repeat(43), 'https://app.example/cb', o,
    ),
    'oauth.exchangeRefreshToken': (c, o) => c.oauth.exchangeRefreshToken('your-client-id', 'mo_rt_x', o),
    'oauth.revoke': (c, o) => c.oauth.revoke('your-client-id', 'mo_rt_x', o),
};

// Set BELOW the client's, so the only deadline that can fire in time is the
// per-call one, and its message names which one it was. A second call with no
// override then has to meet the client's own bound, so a per-call value written
// into the client would show.
test('a per-call timeoutMs bounds every call below the client default', async () => {
    for (const [stallName, stall] of Object.entries(STALLS)) {
        for (const [call, invoke] of Object.entries(PER_CALL)) {
            const client = new VPNDetection({ retries: 0, timeoutMs: 400, cache: false, fetch: stall });
            const label = `${call}, ${stallName}`;
            let started = Date.now();
            await assert.rejects(() => invoke(client, { timeoutMs: 80 }), (err) => {
                assert.ok(err instanceof VPNDetectionError, `${label}: wrong error type`);
                assert.equal(err.kind, 'network', label);
                assert.equal(err.retryable, true, label);
                assert.match(err.message, /timed out after 80ms/, label);
                return true;
            });
            assert.ok(Date.now() - started < 300, `${label}: the per-call deadline did not hold`);
            started = Date.now();
            await assert.rejects(() => invoke(client, {}), (err) => /timed out after 400ms/.test(err.message));
            assert.ok(Date.now() - started >= 350, `${label}: the client's bound fired early`);
        }
    }
});

// Per ATTEMPT, like the client-level one: a retried call gets a fresh budget.
test('a per-call timeoutMs applies to each attempt', async () => {
    let calls = 0;
    const client = new VPNDetection({
        retries: 0,
        timeoutMs: 10_000,
        cache: false,
        fetch: () => {
            calls++;
            return new Promise(() => {});
        },
    });
    await assert.rejects(
        () => client.lookup('45.83.91.1', { retries: 1, timeoutMs: 80 }),
        (err) => err instanceof VPNDetectionError && /timed out after 80ms/.test(err.message),
    );
    assert.equal(calls, 2, 'one attempt plus one retry, each abandoned at its own deadline');
});

// The generator would apply all three credential forms the spec documents, the
// query string included, where access logs and browser history keep it. Asserted
// on what leaves the client, because the request succeeds either way.
test('the key is sent in the Authorization header and nowhere else', async () => {
    const seen = [];
    const fetchFn = async (input) => {
        const url = new URL(input.url);
        seen.push({
            path: url.pathname,
            query: [...url.searchParams.keys()],
            authorization: input.headers.get('authorization'),
            xApiKey: input.headers.get('x-api-key'),
        });
        const body = url.pathname === '/batch'
            ? { results: { '9.9.9.9': { ip: '9.9.9.9', is_vpn: false } }, errors: {} }
            : { ip: '9.9.9.9', is_vpn: false };
        return new Response(JSON.stringify(body), {
            status: 200, headers: { 'content-type': 'application/json' },
        });
    };
    const client = new VPNDetection({ fetch: fetchFn, apiKey: 'SECRET', cache: false });
    await client.lookup('9.9.9.9', { timeoutMs: 5000 });
    await client.lookupBatch(['9.9.9.9']);
    await client.myIp();

    assert.equal(seen.length, 3);
    for (const s of seen) {
        assert.equal(s.authorization, 'Bearer SECRET', s.path);
        assert.deepEqual(s.query, [], `${s.path}: the key, or an option, reached a URL`);
        assert.equal(s.xApiKey, null, `${s.path}: one credential form, not three`);
    }
});

// No key, no header: a page using the free tier sends nothing a preflight would
// have to admit on a lookup.
test('a client without a key sends no Authorization header', async () => {
    const seen = [];
    const fetchFn = async (input) => {
        seen.push([...input.headers.keys()]);
        return new Response(JSON.stringify({ ip: '9.9.9.9', is_vpn: false }), {
            status: 200, headers: { 'content-type': 'application/json' },
        });
    };
    await new VPNDetection({ fetch: fetchFn }).lookup('9.9.9.9');
    await new VPNDetection({ fetch: fetchFn }).myIp();
    assert.deepEqual(seen, [[], []]);
});

// A fetch that answers one fixed body and counts calls, for the two endpoints
// that take no argument.
function countingFetch(body) {
    const state = { calls: 0, urls: [] };
    const fn = async (input) => {
        const url = typeof input === 'string' ? input : input.url;
        state.calls++;
        state.urls.push(new URL(url).pathname);
        return new Response(JSON.stringify(body), {
            status: 200, headers: { 'content-type': 'application/json' },
        });
    };
    return { fetch: fn, state: state };
}

test('myIp asks the server which address you are', async () => {
    const t = countingFetch({ ip: '203.0.113.9', is_vpn: true });
    const client = new VPNDetection({ fetch: t.fetch });
    const result = await client.myIp();
    assert.equal(result.ip, '203.0.113.9');
    assert.equal(result.isVpn, true);
    assert.equal(t.state.urls[0], '/myip');
});

// The cache is keyed by address, and which address this is IS the question, so
// a second call has to ask again.
test('myIp is not cached', async () => {
    const t = countingFetch({ ip: '203.0.113.9', is_vpn: false });
    const client = new VPNDetection({ fetch: t.fetch });
    await client.myIp();
    await client.myIp();
    await client.myIp();
    assert.equal(t.state.calls, 3);
});

test('myEntitlement reports the plan and the usage', async () => {
    const t = countingFetch({
        org_id: '85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61',
        apikey: { id: '0ab424cc-7619-4dad-b027-afacdc2cedb0', expires: null, allowed_cidrs: [] },
        plan: { key: 'max', tier: 'max' },
        usage: {
            requests: 580, quota: 5000000, hard_limit: null,
            window_start: '2026-09-04T07:00:00Z', window_end: '2026-10-04T07:00:00Z',
        },
    });
    const client = new VPNDetection({ fetch: t.fetch, apiKey: 'k' });
    const ent = await client.myEntitlement();
    assert.equal(ent.plan.key, 'max');
    assert.equal(ent.usage.requests, 580);
    // An uncapped plan reports null, which is not zero: zero would read as
    // "stop serving immediately".
    assert.equal(ent.usage.hard_limit, null);
    assert.equal(t.state.urls[0], '/api/v1/entitlement');
});

// Usage is the whole point, so a cached answer is a wrong one within seconds.
test('myEntitlement is not cached', async () => {
    const t = countingFetch({
        org_id: 'f32191d0-ef02-450e-a505-eb5814c35cab',
        apikey: { id: '10c2b437-3aa2-4a63-bd17-8e7c8c7f0def', expires: null, allowed_cidrs: [] },
        plan: { key: 'free', tier: 'free' },
        usage: {
            requests: 1, quota: 2, hard_limit: 2,
            window_start: '2026-09-01T00:00:00Z', window_end: '2026-10-01T00:00:00Z',
        },
    });
    const client = new VPNDetection({ fetch: t.fetch, apiKey: 'k' });
    await client.myEntitlement();
    await client.myEntitlement();
    assert.equal(t.state.calls, 2);
});

// Answers after a delay and counts what it was asked, a batch by the addresses in
// its body, so a request shared or sent twice shows in the count.
function sharingFetch(delayMs, refuse = new Set()) {
    const state = { paths: [], batched: [] };
    const fn = async (input, init) => {
        const request = typeof input === 'string' ? new Request(input, init) : input;
        const path = new URL(request.url).pathname;
        state.paths.push(path);
        await new Promise((r) => setTimeout(r, delayMs));
        if (path === '/batch') {
            const ips = JSON.parse(await request.text()).ips;
            state.batched.push(ips);
            const results = {};
            const errors = {};
            for (const ip of ips) {
                if (refuse.has(ip)) {
                    errors[ip] = { status: 403, error: 'forbidden' };
                } else {
                    results[ip] = { ip: ip, is_vpn: false };
                }
            }
            return Response.json({ results: results, errors: errors });
        }
        const ip = decodeURIComponent(path.slice(1));
        if (refuse.has(ip)) {
            return Response.json({ error: 'forbidden' }, { status: 403 });
        }
        return Response.json({ ip: ip, is_vpn: false });
    };
    return { fetch: fn, state: state };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Long enough that a call started a quarter of it later is still concurrent.
const STAGGER = 400;

test('concurrent misses for one address share one request', async () => {
    const t = sharingFetch(200);
    const client = new VPNDetection({ fetch: t.fetch });

    const answers = await Promise.all(Array.from({ length: 20 }, () => client.lookup('45.83.91.1')));

    assert.deepEqual(t.state.paths, ['/45.83.91.1'], `20 callers sent ${t.state.paths.length} requests`);
    for (const answer of answers) {
        assert.equal(answer.ip, '45.83.91.1');
    }
});

test('a shared failure reaches every waiter and is not cached', async () => {
    const refuse = new Set(['45.83.91.1']);
    const t = sharingFetch(200, refuse);
    const client = new VPNDetection({ fetch: t.fetch, retries: 0 });

    const settled = await Promise.allSettled(Array.from({ length: 5 }, () => client.lookup('45.83.91.1')));

    assert.equal(t.state.paths.length, 1);
    for (const s of settled) {
        assert.equal(s.status, 'rejected');
        assert.equal(s.reason.kind, 'forbidden');
    }
    refuse.clear();
    assert.equal((await client.lookup('45.83.91.1')).ip, '45.83.91.1');
    assert.equal(t.state.paths.length, 2, 'the failure was cached');
});

test('a batch awaits a lookup in flight', async () => {
    const t = sharingFetch(STAGGER);
    const client = new VPNDetection({ fetch: t.fetch });

    const single = client.lookup('45.83.91.1');
    await sleep(STAGGER / 4);
    const batch = await client.lookupBatch(['45.83.91.1', '45.83.91.2']);
    await single;

    assert.equal(batch.get('45.83.91.1').ip, '45.83.91.1');
    assert.equal(batch.get('45.83.91.2').ip, '45.83.91.2');
    assert.deepEqual(t.state.batched, [['45.83.91.2']], 'the batch sent the address in flight again');
    assert.equal(t.state.paths.length, 2);
});

test('a lookup awaits a batch in flight', async () => {
    const t = sharingFetch(STAGGER);
    const client = new VPNDetection({ fetch: t.fetch });

    const batch = client.lookupBatch(['45.83.91.1', '45.83.91.2']);
    await sleep(STAGGER / 4);
    const single = await client.lookup('45.83.91.2');
    await batch;

    assert.equal(single.ip, '45.83.91.2');
    assert.deepEqual(t.state.paths, ['/batch']);
});

test('a lookup takes the failure of the batch it joined', async () => {
    const t = sharingFetch(STAGGER, new Set(['45.83.91.2']));
    const client = new VPNDetection({ fetch: t.fetch });

    const batch = client.lookupBatch(['45.83.91.1', '45.83.91.2']);
    await sleep(STAGGER / 4);
    await assert.rejects(client.lookup('45.83.91.2'), (err) => err.kind === 'forbidden');
    const answers = await batch;

    assert.equal(answers.get('45.83.91.2').kind, 'forbidden');
    assert.deepEqual(t.state.paths, ['/batch']);
});

// Held for its TTL and asked again after it, so neither a cache that expires at once
// nor one that never does passes.
test('the cache holds an answer for its TTL and no longer', async () => {
    const t = sharingFetch(0);
    const client = new VPNDetection({ fetch: t.fetch, cache: { ttlMs: 300 } });

    await client.lookup('45.83.91.1');
    await sleep(60);
    await client.lookup('45.83.91.1');
    await client.lookupBatch(['45.83.91.1']);
    assert.equal(t.state.paths.length, 1, 'asked again inside the TTL');
    await sleep(400);
    await client.lookup('45.83.91.1');
    assert.equal(t.state.paths.length, 2, 'not asked again after the TTL');
});

test('a client without a cache shares nothing', async () => {
    const t = sharingFetch(100);
    const client = new VPNDetection({ fetch: t.fetch, cache: false });

    await Promise.all([
        ...Array.from({ length: 3 }, () => client.lookup('45.83.91.1')),
        client.lookupBatch(['45.83.91.1']),
        client.lookupBatch(['45.83.91.1']),
    ]);

    assert.equal(t.state.paths.length, 5);
});

// Answers every call the way its path expects and records the paths, so a
// doubled slash shows up as a path rather than as whatever a server makes of it.
function pathRecordingFetch() {
    const paths = [];
    const fn = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        const path = new URL(request.url).pathname;
        paths.push(path);
        const body = path.endsWith('batch')
            ? { results: { '9.9.9.9': { ip: '9.9.9.9', is_vpn: false } }, errors: {} }
            : path.endsWith('oauth-authorization-server')
                ? { issuer: 'x', authorization_endpoint: 'x', token_endpoint: 'x' }
                : path.endsWith('entitlement')
                    ? {
                        org_id: 'o', apikey: { id: 'a', expires: null, allowed_cidrs: [] },
                        plan: { key: 'max', tier: 'max' },
                        usage: {
                            requests: 1, quota: 2, hard_limit: null,
                            window_start: '2026-10-01T00:00:00Z', window_end: '2026-11-01T00:00:00Z',
                        },
                    }
                    : { ip: '8.8.8.8', is_vpn: false };
        return new Response(JSON.stringify(body), {
            status: 200, headers: { 'content-type': 'application/json' },
        });
    };
    return { fetch: fn, paths: paths };
}

// Every path the client appends starts with a slash, and a doubled one
// (//8.8.8.8, //batch) is another path, which the API answers with a redirect.
test('every trailing slash on the base URL is dropped', async (t) => {
    for (const suffix of ['/', '//', '///']) {
        await t.test(JSON.stringify(suffix), async () => {
            const stub = pathRecordingFetch();
            const client = new VPNDetection({
                baseUrl: `https://api.example.test${suffix}`, apiKey: 'k', fetch: stub.fetch, retries: 0,
            });
            await client.lookup('8.8.8.8');
            await client.lookupBatch(['9.9.9.9']);
            await client.myIp();
            await client.myEntitlement();
            await client.oauth.metadata();
            assert.deepEqual(stub.paths, [
                '/8.8.8.8', '/batch', '/myip', '/api/v1/entitlement', '/.well-known/oauth-authorization-server',
            ]);
            const url = new URL(client.oauth.authorizationUrl('x', 'https://app.example/cb', 'c'.repeat(43)));
            assert.equal(url.pathname, '/oauth/authorize');
        });
    }
});

// setTimeout runs 0, a negative, NaN, Infinity and anything past 2^31 - 1 ms as
// at once, so each would fail every call as a timeout 1 ms in. Refused where set
// instead, per call before a bogon or a cached address can answer.
const IMPOSSIBLE_TIMEOUTS = [0, -1, NaN, Infinity, 2 ** 31, '5000'];

test('a timeout no attempt can meet is refused on the client', () => {
    for (const timeoutMs of IMPOSSIBLE_TIMEOUTS) {
        assert.throws(() => new VPNDetection({ timeoutMs: timeoutMs }),
            (err) => err instanceof VPNDetectionError && err.kind === 'bad_request', String(timeoutMs));
    }
    for (const timeoutMs of [1, 2 ** 31 - 1]) {
        assert.doesNotThrow(() => new VPNDetection({ timeoutMs: timeoutMs }), String(timeoutMs));
    }
});

test('a timeout no attempt can meet is refused per call, before anything answers', async () => {
    const stub = pathRecordingFetch();
    const client = new VPNDetection({ apiKey: 'k', fetch: stub.fetch, retries: 0 });
    await client.lookup('8.8.8.8');
    const asked = stub.paths.length;
    const calls = {
        'a bogon': (o) => client.lookup('10.0.0.1', o),
        'a cached address': (o) => client.lookup('8.8.8.8', o),
        'a batch': (o) => client.lookupBatch(['10.0.0.1', '8.8.8.8'], o),
        'myIp': (o) => client.myIp(o),
        'myEntitlement': (o) => client.myEntitlement(o),
        'metadata': (o) => client.oauth.metadata(o),
        'revoke': (o) => client.oauth.revoke('your-client-id', 'mo_rt_x', o),
        'exchangeRefreshToken': (o) => client.oauth.exchangeRefreshToken('your-client-id', 'mo_rt_x', o),
        'exchangeAuthorizationCode': (o) => client.oauth.exchangeAuthorizationCode(
            'your-client-id', 'mo_ac_x', 'v'.repeat(43), 'https://app.example/cb', o,
        ),
    };
    for (const timeoutMs of IMPOSSIBLE_TIMEOUTS) {
        for (const [name, call] of Object.entries(calls)) {
            await assert.rejects(call({ timeoutMs: timeoutMs }),
                (err) => err instanceof VPNDetectionError && err.kind === 'bad_request',
                `${name}: ${timeoutMs}`);
        }
    }
    assert.equal(stub.paths.length, asked, 'a refused timeout sent a request');
});

// setTimeout runs a delay past 2^31 - 1 ms at once, and Node also prints a
// TimeoutOverflowWarning, so a Retry-After of 2147484 s or more is waited out on
// the backoff alone, still a throttle, and never handed to setTimeout.
test('a Retry-After past what setTimeout holds waits the backoff, with no warning', async (t) => {
    const warnings = timeoutWarnings(t);
    const paths = [];
    const fetch = async (input) => {
        const url = new URL(typeof input === 'string' ? input : input.url);
        paths.push(url.pathname);
        if (paths.length === 1) {
            return new Response(JSON.stringify({ error: 'rate limit exceeded' }), {
                status: 429, headers: { 'content-type': 'application/json', 'retry-after': '2147484' },
            });
        }
        return new Response(JSON.stringify({ ip: '9.9.9.9', is_vpn: false }), {
            status: 200, headers: { 'content-type': 'application/json' },
        });
    };
    const client = new VPNDetection({ fetch: fetch, retries: 1, cache: false });

    assert.equal((await client.lookup('9.9.9.9')).ip, '9.9.9.9');
    assert.deepEqual(paths, ['/9.9.9.9', '/9.9.9.9']);
    assert.deepEqual(warnings, []);
});

// p-retry calls onFailedAttempt before it checks retriesLeft, so a wait there
// with no guard would hold a call for its last attempt's Retry-After and only
// then fail.
test('a Retry-After is not waited out when no retry follows', async () => {
    const fetch = async () => new Response(JSON.stringify({ error: 'rate limit exceeded' }), {
        status: 429, headers: { 'content-type': 'application/json', 'retry-after': '3' },
    });
    // One retry waits the header once, then p-retry's own 1 s backoff.
    for (const [retries, least, most] of [[0, 0, 1000], [1, 3000, 6000]]) {
        const client = new VPNDetection({ fetch: fetch, cache: false, retries: retries });
        const started = Date.now();
        await assert.rejects(client.lookup('9.9.9.9'), (err) => err.kind === 'rate_limited');
        const elapsed = Date.now() - started;
        assert.ok(elapsed >= least && elapsed < most,
            `retries ${retries} failed after ${elapsed} ms, want ${least} to ${most} ms`);
    }
});

// A transport failure is a retried network error naming what the runtime said,
// which in a browser is the only hint between offline, CORS and a blocked request.
test('a request that gets no answer is a retried network error carrying its cause', async () => {
    let calls = 0;
    const fetch = async () => {
        calls++;
        throw new TypeError('Failed to fetch');
    };
    const client = new VPNDetection({ fetch: fetch, cache: false, retries: 1 });
    await assert.rejects(client.lookup('9.9.9.9'), (err) => {
        assert.ok(err instanceof VPNDetectionError);
        assert.equal(err.kind, 'network');
        assert.equal(err.retryable, true);
        assert.match(err.message, /Failed to fetch/);
        return true;
    });
    assert.equal(calls, 2);
});

// The global fetch is looked up on each request, so a page wrapping it after the
// client is built still sees what this client sends.
test('the global fetch is read per request, not when the client is built', async (t) => {
    const original = globalThis.fetch;
    t.after(() => {
        globalThis.fetch = original;
    });
    const client = new VPNDetection({ cache: false });
    const seen = [];
    globalThis.fetch = async (input) => {
        seen.push(new URL(input.url).pathname);
        return new Response(JSON.stringify({ ip: '9.9.9.9', is_vpn: false }), {
            status: 200, headers: { 'content-type': 'application/json' },
        });
    };
    assert.equal((await client.lookup('9.9.9.9')).ip, '9.9.9.9');
    assert.deepEqual(seen, ['/9.9.9.9']);
});

function timeoutWarnings(t) {
    const seen = [];
    const listener = (warning) => {
        if (warning.name === 'TimeoutOverflowWarning') {
            seen.push(warning.message);
        }
    };
    process.on('warning', listener);
    t.after(() => process.off('warning', listener));
    return seen;
}
