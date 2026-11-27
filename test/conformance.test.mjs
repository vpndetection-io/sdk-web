// The conformance corpus in testdata/, which every VPNDetection client library
// asserts, so a behavior that drifts fails here rather than two libraries quietly
// disagreeing about one address. Runs against dist/, which is what ships.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { VPNDetection, VPNDetectionError, isBogon } from '../dist/index.js';

const data = JSON.parse(readFileSync(new URL('../testdata/testdata.json', import.meta.url), 'utf8'));

const camel = (s) => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());

// A fetch stand-in that answers from a table and counts what it was asked for,
// so "never touched the network" is asserted rather than assumed.
function stubFetch(routes) {
    const calls = [];
    const fn = async (input, init) => {
        const url = typeof input === 'string' ? input : input.url;
        calls.push(url);
        if (new URL(url).pathname === '/batch') {
            return batchResponse(routes, await bodyOf(input, init));
        }
        const ip = decodeURIComponent(new URL(url).pathname.slice(1));
        const r = routes[ip];
        if (r === undefined) {
            return new Response(JSON.stringify({ error: 'not a valid IP address' }), {
                status: 400, headers: { 'content-type': 'application/json' },
            });
        }
        return new Response(JSON.stringify(r.body), {
            status: r.status ?? 200,
            headers: { 'content-type': 'application/json', ...(r.headers ?? {}) },
        });
    };
    return { fetch: fn, calls: calls };
}

// The request body, whichever way the client handed it to fetch: as a Request
// object, or as an init alongside a URL string.
async function bodyOf(input, init) {
    if (typeof input !== 'string' && typeof input.text === 'function') {
        return input.text();
    }
    return typeof init?.body === 'string' ? init.body : '';
}

// A POST /batch is answered the way the API answers one: every address the
// table knows is a result if its route is a 200 and an entry error otherwise,
// and an unknown address is the 400 the API gives a string that is not one.
function batchResponse(routes, body) {
    const results = {};
    const errors = {};
    for (const ip of JSON.parse(body || '{}').ips ?? []) {
        const r = routes[ip];
        if (r === undefined) {
            errors[ip] = { status: 400, error: 'not a valid IP address' };
        } else if ((r.status ?? 200) === 200) {
            results[ip] = r.body;
        } else {
            errors[ip] = { status: r.status, error: r.body.error };
        }
    }
    return new Response(JSON.stringify({ results: results, errors: errors }), {
        status: 200, headers: { 'content-type': 'application/json' },
    });
}

test('isBogon matches the canonical ranges', () => {
    for (const c of data.isBogon) {
        assert.equal(isBogon(c.ip), c.expect, `${c.ip} (${c.why})`);
    }
});

// A server listening on :: sees every IPv4 visitor as ::ffff:a.b.c.d, which read
// whole is inside ::ffff:0:0/96, so an address a page gets from such a server would
// otherwise be answered as a bogon with no request made.
test('an IPv4-mapped address is judged, sent and cached as the IPv4 address it carries', async () => {
    for (const c of data.ipv4Mapped) {
        assert.equal(isBogon(c.ip), c.expect, `${c.ip} (${c.why})`);
        const routes = { [c.carries]: { body: { ip: c.carries, is_vpn: true } } };

        const stub = stubFetch(routes);
        const client = new VPNDetection({ fetch: stub.fetch });
        const r = await client.lookup(c.ip);
        assert.equal(r.isBogon, c.expect, c.ip);
        assert.equal(r.ip, c.carries, c.ip);
        await client.lookup(c.carries);
        assert.deepEqual(stub.calls.map((u) => new URL(u).pathname), c.expect ? [] : [`/${c.carries}`], c.ip);

        const sent = [];
        const batchStub = stubFetch(routes);
        const recording = async (input, init) => {
            const url = typeof input === 'string' ? input : input.url;
            if (new URL(url).pathname === '/batch') {
                const request = typeof input === 'string' ? input : input.clone();
                sent.push(...JSON.parse(await bodyOf(request, init)).ips);
            }
            return batchStub.fetch(input, init);
        };
        const uncached = new VPNDetection({ fetch: recording, cache: false });
        const asked = [...new Set([c.ip, c.carries])];
        const batch = await uncached.lookupBatch(asked);
        assert.deepEqual([...batch.keys()], asked, c.ip);
        assert.equal(batch.get(c.ip).ip, c.carries, c.ip);
        assert.deepEqual(sent, c.expect ? [] : [c.carries], c.ip);
    }
});

test('a bogon is answered locally in the full max shape', async () => {
    const stub = stubFetch({});
    const c = new VPNDetection({ fetch: stub.fetch });
    const r = await c.lookup('10.0.0.1');

    assert.equal(r.isBogon, true);
    assert.equal(r.ip, '10.0.0.1');
    for (const f of data.bogonResponse.flagsFalse) {
        assert.equal(r[camel(f)], false, `${f} must be present and false`);
    }
    for (const o of data.bogonResponse.emptyObjects) {
        assert.deepEqual(r[camel(o)], {}, `${o} must be present and empty`);
    }
    assert.deepEqual(r.location, data.bogonResponse.location, 'location must carry every key, empty');
    assert.deepEqual(r.asn, data.bogonResponse.asn, 'asn must carry every key, empty');
    assert.deepEqual(r.web, data.bogonResponse.web, 'web must be present and an empty list');
    assert.equal(r.hostname, data.bogonResponse.hostname, 'hostname must be present and empty');
    assert.deepEqual(r.company, data.bogonResponse.company, 'company must carry every key, empty');
    assert.deepEqual(r.abuse, data.bogonResponse.abuse, 'abuse must carry every key, empty');
    assert.equal(stub.calls.length, 0, 'a bogon must not reach the network');
});

// Every member a case's `expect` can name. A key outside this list fails the
// case rather than passing it unread, so a member the corpus adds is asserted
// here before it can pass vacuously.
const DETAIL_KEYS = [
    'vpn', 'hosting', 'dcproxy', 'pubproxy', 'carrier', 'satellite', 'ssh', 'smtp', 'web', 'dns_resolver',
    'bittorrent', 'bot', 'location', 'asn', 'company', 'abuse', 'hostname',
];
const EXPECT_KEYS = ['ip', 'isBogon', 'present', 'absent', 'emptyPresent', ...DETAIL_KEYS];

test('lookup preserves absent-versus-false across every plan shape', async () => {
    for (const c of data.lookup) {
        assert.deepEqual(Object.keys(c.expect).filter((k) => !EXPECT_KEYS.includes(k)), [], `${c.name}: unread expect keys`);
        const stub = stubFetch({ [c.body.ip]: { status: c.status, body: c.body } });
        const client = new VPNDetection({ fetch: stub.fetch });
        const r = await client.lookup(c.body.ip);

        assert.equal(r.ip, c.expect.ip, c.name);
        assert.equal(r.isBogon, c.expect.isBogon, c.name);

        for (const [k, v] of Object.entries(c.expect.present ?? {})) {
            assert.equal(r[camel(k)], v, `${c.name}: ${k} should be ${v}`);
        }
        for (const k of c.expect.absent ?? []) {
            assert.equal(r[camel(k)], undefined, `${c.name}: ${k} must be ABSENT, not false`);
        }
        for (const k of c.expect.emptyPresent ?? []) {
            assert.deepEqual(r[camel(k)], {}, `${c.name}: ${k} must be present and empty`);
        }
        for (const obj of DETAIL_KEYS) {
            if (c.expect[obj] !== undefined) {
                // The AS's type is typed string, so an answer without one reads it as empty; raw is as served.
                const want = obj === 'asn' ? { ...c.expect.asn, type: c.expect.asn.type ?? '' } : c.expect[obj];
                assert.deepEqual(r[camel(obj)], want, `${c.name}: ${obj}`);
            }
        }
        if (c.expect.asn !== undefined) {
            assert.deepEqual(r.raw.asn, c.expect.asn, `${c.name}: raw.asn is as served`);
        }
    }
});

test('a 429 is classified by Retry-After, not by its status', async () => {
    for (const c of data.errors) {
        const stub = stubFetch({
            '1.1.1.1': { status: c.status, body: c.body, headers: c.headers },
        });
        // No retries, so a retryable error still surfaces rather than looping.
        const client = new VPNDetection({ fetch: stub.fetch, retries: 0 });
        await assert.rejects(
            () => client.lookup('1.1.1.1'),
            (err) => {
                assert.ok(err instanceof VPNDetectionError, `${c.name}: wrong error type`);
                assert.equal(err.kind, c.expect.kind, c.name);
                assert.equal(err.retryable, c.expect.retryable, `${c.name}: retryable`);
                if (c.expect.message !== undefined) {
                    assert.equal(err.message, c.expect.message, `${c.name}: message`);
                }
                if (c.expect.retryAfterSeconds !== undefined) {
                    assert.equal(err.retryAfterSeconds, c.expect.retryAfterSeconds, c.name);
                }
                return true;
            },
        );
    }
});

// With retries on, so a classifier that marked a client error retryable shows as
// a second request rather than passing because nothing could retry anyway.
test('a non-retryable error is sent once with retries on', async () => {
    for (const c of data.errors.filter((e) => !e.expect.retryable)) {
        const stub = stubFetch({ '1.1.1.1': { status: c.status, body: c.body, headers: c.headers } });
        const client = new VPNDetection({ fetch: stub.fetch, retries: 2 });
        await assert.rejects(() => client.lookup('1.1.1.1'), (err) => err.kind === c.expect.kind);
        assert.equal(stub.calls.length, 1, `${c.name} was retried`);
    }
});

test('batch dedupes, short-circuits bogons and keys by address', async () => {
    const c = data.batch.find((b) => b.name === 'dedup-bogon-and-order-free-keying');
    const stub = stubFetch({
        '1.1.1.1': { body: { ip: '1.1.1.1', is_vpn: false } },
        '8.8.8.8': { body: { ip: '8.8.8.8', is_vpn: false } },
    });
    const client = new VPNDetection({ fetch: stub.fetch });
    const got = await client.lookupBatch(c.input);

    assert.deepEqual([...got.keys()], c.expect.keys);
    assert.equal(stub.calls.length, c.expect.httpRequests);
    for (const k of c.expect.bogonKeys) {
        assert.equal(got.get(k).isBogon, true, `${k} should be a local answer`);
    }
});

test('one bad address does not lose the rest of the batch', async () => {
    const c = data.batch.find((b) => b.name === 'partial-failure-does-not-fail-the-batch');
    const stub = stubFetch({ '1.1.1.1': { body: { ip: '1.1.1.1', is_vpn: false } } });
    const client = new VPNDetection({ fetch: stub.fetch, retries: 0 });
    const got = await client.lookupBatch(c.input);

    assert.deepEqual([...got.keys()], c.expect.keys);
    for (const k of c.expect.errorKeys) {
        assert.ok(got.get(k) instanceof VPNDetectionError, `${k} should carry its error`);
        assert.equal(got.get(k).kind, c.expect.errorKinds[k], `${k} should be ${c.expect.errorKinds[k]}`);
    }
    assert.equal(got.get('1.1.1.1').isVpn, false, 'the good address still answered');
});

test('a cache hit issues no second request', async () => {
    const c = data.batch.find((b) => b.name === 'cache-hit-issues-no-second-request');
    const stub = stubFetch({ '1.1.1.1': { body: { ip: '1.1.1.1', is_vpn: false } } });
    const client = new VPNDetection({ fetch: stub.fetch });

    for (let i = 0; i < c.repeat; i++) {
        await client.lookupBatch(c.input);
    }
    assert.equal(stub.calls.length, c.expect.httpRequests);
});

// One POST /batch per chunk of 1000, and no cap on what a caller passes.
test('a large batch is sent in chunks of a thousand, whatever its size', async (t) => {
    for (const name of ['chunks-of-one-thousand', 'uncapped-input-is-chunked']) {
        await t.test(name, async () => {
            const c = data.batch.find((b) => b.name === name);
            const posts = [];
            const fetchFn = async (input) => {
                const sent = JSON.parse(await input.text()).ips;
                posts.push({ method: input.method, path: new URL(input.url).pathname, ips: sent });
                const results = Object.fromEntries(sent.map((ip) => [ip, { ip: ip, is_vpn: false }]));
                return new Response(JSON.stringify({ results: results, errors: {} }), {
                    status: 200, headers: { 'content-type': 'application/json' },
                });
            };
            const client = new VPNDetection({ fetch: fetchFn, cache: false });
            const got = await client.lookupBatch(c.input);

            assert.equal(posts.length, c.expect.httpRequests, 'one request per chunk');
            for (const post of posts) {
                assert.equal(`${post.method} ${post.path}`, 'POST /batch');
                assert.ok(post.ips.length <= 1000, `a chunk carried ${post.ips.length} addresses`);
            }
            const sent = posts.flatMap((p) => p.ips);
            assert.deepEqual(sent.sort(), [...c.input].sort(), 'each address sent once');
            assert.equal(got.size, c.expect.keyCount);
            for (const ip of c.input) {
                assert.equal(got.get(ip).ip, ip, `${ip} should be answered for itself`);
            }
        });
    }
});

// A per-entry failure carries no headers, so its 429 can only be a spent
// allowance, and a 500 is the server's; neither is retried per entry, because
// retries belong to the call and the call succeeded.
test('an entry error is classified by its status', async () => {
    const c = data.batch.find((b) => b.name === 'an-entry-error-is-classified-by-its-status');
    const stub = stubFetch({
        '1.1.1.1': { body: { ip: '1.1.1.1', is_vpn: false } },
        '8.8.8.8': {
            status: 429, body: { error: 'overage cap reached; raise or remove it in Billing' },
        },
        '9.9.9.9': { status: 500, body: { error: 'lookup failed' } },
    });
    const client = new VPNDetection({ fetch: stub.fetch, retries: 3 });
    const got = await client.lookupBatch(c.input);

    assert.deepEqual([...got.keys()], c.expect.keys);
    for (const [ip, kind] of Object.entries(c.expect.errorKinds)) {
        assert.ok(got.get(ip) instanceof VPNDetectionError, `${ip} should carry its error`);
        assert.equal(got.get(ip).kind, kind, `${ip} should be ${kind}`);
    }
    assert.equal(stub.calls.length, c.expect.httpRequests);
});

test('two clients never share a cached answer', async () => {
    const stub = stubFetch({ '1.1.1.1': { body: { ip: '1.1.1.1', is_vpn: false } } });
    const a = new VPNDetection({ fetch: stub.fetch, apiKey: 'key-a' });
    const b = new VPNDetection({ fetch: stub.fetch, apiKey: 'key-b' });

    await a.lookup('1.1.1.1');
    await b.lookup('1.1.1.1');
    // Two keys can be on different plans and so entitled to different fields;
    // a shared cache would serve one of them the other's shape.
    assert.equal(stub.calls.length, 2);
});

test('caching can be turned off', async () => {
    const stub = stubFetch({ '1.1.1.1': { body: { ip: '1.1.1.1', is_vpn: false } } });
    const client = new VPNDetection({ fetch: stub.fetch, cache: false });
    await client.lookup('1.1.1.1');
    await client.lookup('1.1.1.1');
    assert.equal(stub.calls.length, 2);
});

// The browser SDK has no database calls, so it reads the entitlement's cases
// and names the rest as not its own.
test('a closed vocabulary hands back a value it was not built with', async (t) => {
    const cases = data.vocabulary.cases;
    assert.ok(cases.length >= 6);
    let read = 0;
    for (const c of cases) {
        if (c.call !== 'myEntitlement') {
            t.diagnostic(`${c.name}: ${c.call} is not a browser call`);
            continue;
        }
        const client = new VPNDetection({
            apiKey: 'k',
            retries: 0,
            fetch: async (input) => {
                const url = typeof input === 'string' ? input : input.url;
                assert.equal(new URL(url).pathname, '/api/v1/entitlement', c.name);
                return new Response(JSON.stringify(c.answer), { headers: { 'content-type': 'application/json' } });
            },
        });
        const answer = await client.myEntitlement();
        for (const [member, value] of Object.entries(c.expect)) {
            assert.deepEqual(member.split('.').reduce((v, step) => v[step], answer), value, `${c.name}: ${member}`);
        }
        read += 1;
    }
    assert.ok(read >= 2);
});
