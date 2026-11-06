// The cache's persistent tier: read after the in-memory cache misses and before
// the network, written after each answer the API serves, and keyed so that two
// clients holding different keys never read each other's answers from it.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { VPNDetection, VPNDetectionError } from '../dist/index.js';

const HOUR = 60 * 60 * 1000;

// A store in a Map, recording what it was asked. `async` makes every call answer
// a promise, as chrome.storage does; otherwise it answers at once, as
// sessionStorage does.
function mapStore({ async = false, entries = new Map() } = {}) {
    const log = { gets: [], sets: [] };
    const answer = (value) => (async ? Promise.resolve(value) : value);
    return {
        entries: entries,
        log: log,
        get: (key) => {
            log.gets.push(key);
            return answer(entries.get(key));
        },
        set: (key, result, ttlMs) => {
            log.sets.push({ key: key, ttlMs: ttlMs });
            entries.set(key, structuredClone(result));
            return answer(undefined);
        },
    };
}

// Answers a lookup, a batch, myip and the entitlement, counting what it was asked;
// an address in `refuse` is a 403, on its own and inside a batch.
function api(refuse = new Set(), delayMs = 0) {
    const state = { paths: [], batched: [] };
    const fetch = async (input) => {
        const path = new URL(input.url).pathname;
        state.paths.push(path);
        await new Promise((r) => setTimeout(r, delayMs));
        if (path === '/batch') {
            const ips = JSON.parse(await input.text()).ips;
            state.batched.push(ips);
            const results = {};
            const errors = {};
            for (const ip of ips) {
                if (refuse.has(ip)) {
                    errors[ip] = { status: 403, error: 'forbidden' };
                } else {
                    results[ip] = { ip: ip, is_vpn: true, is_tor: false };
                }
            }
            return Response.json({ results: results, errors: errors });
        }
        if (path === '/api/v1/entitlement') {
            return Response.json({
                org_id: 'o', apikey: { id: 'a', expires: null, allowed_cidrs: [] },
                plan: { key: 'max', tier: 'max' },
                usage: {
                    requests: 1, quota: 2, hard_limit: null,
                    window_start: '2026-10-01T00:00:00Z', window_end: '2026-11-01T00:00:00Z',
                },
            });
        }
        const ip = path === '/myip' ? '203.0.113.9' : decodeURIComponent(path.slice(1));
        if (refuse.has(ip)) {
            return Response.json({ error: 'forbidden' }, { status: 403 });
        }
        return Response.json({ ip: ip, is_vpn: true, is_tor: false });
    };
    return { fetch: fetch, state: state };
}

const keyOf = (store, ip) => [...store.entries.keys()].find((key) => key.endsWith(`:${ip}`));

test('a served answer is written to the store, with the cache TTL', async () => {
    for (const async of [false, true]) {
        const store = mapStore({ async: async });
        const server = api();
        const client = new VPNDetection({ fetch: server.fetch, cache: { store: store, ttlMs: 5000 } });

        const result = await client.lookup('45.83.91.1');

        assert.equal(result.isVpn, true);
        assert.equal(store.log.sets.length, 1, 'written once');
        assert.match(store.log.sets[0].key, /^[0-9a-f]{16}:45\.83\.91\.1$/);
        assert.equal(store.log.sets[0].ttlMs, 5000);
        const raw = store.entries.get(store.log.sets[0].key).raw;
        assert.deepEqual(raw, { ip: '45.83.91.1', is_vpn: true, is_tor: false });
    }
});

// A page reload or an extension's worker starting again is a NEW client over the
// same store: it answers from the store with no request.
test('a new client over the same store answers without a request', async () => {
    for (const async of [false, true]) {
        const store = mapStore({ async: async });
        const first = api();
        await new VPNDetection({ fetch: first.fetch, cache: { store: store } }).lookup('45.83.91.1');

        const second = api();
        const client = new VPNDetection({ fetch: second.fetch, cache: { store: store } });
        const result = await client.lookup('45.83.91.1');

        assert.deepEqual(second.state.paths, [], 'the store was not read before the network');
        assert.equal(result.ip, '45.83.91.1');
        assert.equal(result.isVpn, true);
        assert.equal(result.isTor, false);
        assert.equal(result.isBogon, false);
        assert.equal(result.isHosting, undefined, 'absent stays absent through the store');
        assert.equal(store.log.sets.length, 1, 'an answer from the store is not written back');
        // The in-memory tier holds it now: no second read of the store either.
        await client.lookup('45.83.91.1');
        assert.equal(store.log.gets.filter((key) => key.endsWith(':45.83.91.1')).length, 2);
    }
});

test('the in-memory cache answers before the store is read', async () => {
    const store = mapStore();
    const server = api();
    const client = new VPNDetection({ fetch: server.fetch, cache: { store: store } });

    await client.lookup('45.83.91.1');
    await client.lookup('45.83.91.1');
    await client.lookupBatch(['45.83.91.1']);

    assert.equal(store.log.gets.length, 1);
    assert.deepEqual(server.state.paths, ['/45.83.91.1']);
});

test('bogons, errors, myIp and myEntitlement never reach the store', async () => {
    const store = mapStore();
    const server = api(new Set(['45.83.91.2']));
    const client = new VPNDetection({ fetch: server.fetch, apiKey: 'k', retries: 0, cache: { store: store } });

    assert.equal((await client.lookup('10.0.0.1')).isBogon, true);
    await assert.rejects(client.lookup('45.83.91.2'), (err) => err.kind === 'forbidden');
    await client.myIp();
    await client.myEntitlement();
    const batch = await client.lookupBatch(['192.168.1.1', '45.83.91.2']);
    assert.equal(batch.get('192.168.1.1').isBogon, true);
    assert.equal(batch.get('45.83.91.2').kind, 'forbidden');

    assert.deepEqual(store.log.sets, []);
    assert.ok(store.log.gets.every((key) => key.endsWith(':45.83.91.2')), `read ${store.log.gets.join(', ')}`);
});

// Clients holding different keys can be on different plans and so entitled to
// different fields: a keyless answer read back by a keyed client would hand it
// the keyless shape.
test('clients with different keys or base URLs never read each other from one store', async () => {
    const store = mapStore();
    const clients = [
        new VPNDetection({ fetch: api().fetch, cache: { store: store } }),
        new VPNDetection({ fetch: api().fetch, apiKey: 'key-a', cache: { store: store } }),
        new VPNDetection({ fetch: api().fetch, apiKey: 'key-b', cache: { store: store } }),
        new VPNDetection({
            fetch: api().fetch, apiKey: 'key-a', baseUrl: 'https://api.example.test', cache: { store: store },
        }),
    ];
    for (const client of clients) {
        await client.lookup('45.83.91.1');
    }
    const scopes = new Set(store.log.sets.map((set) => set.key.split(':')[0]));
    assert.equal(scopes.size, clients.length, 'two clients wrote under one scope');
    for (const set of store.log.sets) {
        assert.ok(!set.key.includes('key-a') && !set.key.includes('key-b'), `${set.key} holds the key`);
    }

    // The same key, base URL and store: one client's answer is the other's, as
    // across a page reload. A trailing slash on the base URL is the same URL.
    const server = api();
    const again = new VPNDetection({
        fetch: server.fetch, apiKey: ' key-a ', baseUrl: 'https://api.vpndetection.io/',
        cache: { store: store },
    });
    await again.lookup('45.83.91.1');
    assert.deepEqual(server.state.paths, []);
});

test('a batch reads the store for what it leads, sends only the rest, and writes what it got', async () => {
    for (const async of [false, true]) {
        const store = mapStore({ async: async });
        await new VPNDetection({ fetch: api().fetch, cache: { store: store } }).lookup('45.83.91.1');

        const server = api(new Set(['45.83.91.3']));
        const client = new VPNDetection({ fetch: server.fetch, retries: 0, cache: { store: store } });
        const asked = ['45.83.91.1', '45.83.91.2', '10.0.0.1', '45.83.91.3', '45.83.91.2'];
        const got = await client.lookupBatch(asked);

        assert.deepEqual([...got.keys()], ['45.83.91.1', '45.83.91.2', '10.0.0.1', '45.83.91.3']);
        assert.deepEqual(server.state.batched, [['45.83.91.2', '45.83.91.3']], 'the stored address was sent');
        assert.equal(got.get('45.83.91.1').isVpn, true);
        assert.equal(got.get('45.83.91.2').isVpn, true);
        assert.equal(got.get('10.0.0.1').isBogon, true);
        assert.ok(got.get('45.83.91.3') instanceof VPNDetectionError);
        assert.deepEqual(store.log.sets.map((set) => set.key.split(':').slice(1).join(':')),
            ['45.83.91.1', '45.83.91.2'], 'what was written');
        assert.ok(keyOf(store, '45.83.91.2'), 'the batch answer is in the store');
    }
});

// The store is read inside the shared request, so twenty callers missing at once
// still cost one store read and one request.
test('concurrent misses share one store read and one request', async () => {
    const store = mapStore({ async: true });
    const server = api(new Set(), 100);
    const client = new VPNDetection({ fetch: server.fetch, cache: { store: store } });

    const answers = await Promise.all(Array.from({ length: 20 }, () => client.lookup('45.83.91.1')));

    assert.equal(answers.length, 20);
    assert.equal(store.log.gets.length, 1);
    assert.deepEqual(server.state.paths, ['/45.83.91.1']);
    assert.equal(store.log.sets.length, 1);
});

// A cache is never a source of errors: a store that fails costs a request, never
// an answer.
test('a store that throws or rejects reads as a miss, and a failed write is dropped', async () => {
    const failures = {
        'throws': () => {
            throw new Error('quota exceeded');
        },
        'rejects': () => Promise.reject(new Error('the extension context was invalidated')),
    };
    for (const [name, fail] of Object.entries(failures)) {
        const server = api();
        const client = new VPNDetection({ fetch: server.fetch, cache: { store: { get: fail, set: fail } } });
        assert.equal((await client.lookup('45.83.91.1')).isVpn, true, name);
        const batch = await client.lookupBatch(['45.83.91.2', '45.83.91.3']);
        assert.equal(batch.get('45.83.91.2').isVpn, true, name);
        assert.deepEqual(server.state.paths, ['/45.83.91.1', '/batch'], name);
    }
});

// What a store hands back is read the way an answer off the wire is: anything
// that is not a lookup answer is a miss, and the served answer replaces it.
test('a stored entry that is not a lookup answer is a miss', async () => {
    const entries = [undefined, null, 'x', 5, {}, { raw: {} }, { raw: { ip: '45.83.91.1', is_vpn: 'yes' } },
        { ip: '45.83.91.1', isVpn: true }];
    for (const entry of entries) {
        const store = mapStore();
        const server = api();
        const probe = new VPNDetection({ fetch: api().fetch, cache: { store: store } });
        await probe.lookup('45.83.91.1');
        const key = keyOf(store, '45.83.91.1');
        store.entries.set(key, entry);

        const client = new VPNDetection({ fetch: server.fetch, cache: { store: store } });
        const result = await client.lookup('45.83.91.1');

        assert.equal(result.isVpn, true, JSON.stringify(entry));
        assert.deepEqual(server.state.paths, ['/45.83.91.1'], JSON.stringify(entry));
        assert.equal(store.entries.get(key).isVpn, true, `${JSON.stringify(entry)} was not replaced`);
    }
});

test('a store that is not a get and a set is refused where the client is built', () => {
    for (const store of [5, 'x', {}, { get: () => undefined }, { set: () => undefined }, { get: 1, set: 2 }]) {
        assert.throws(() => new VPNDetection({ cache: { store: store } }),
            (err) => err instanceof VPNDetectionError && err.kind === 'bad_request', JSON.stringify(store));
    }
    for (const store of [undefined, null]) {
        assert.doesNotThrow(() => new VPNDetection({ cache: { store: store } }), String(store));
    }
});

test('the default TTL reaches the store', async () => {
    const store = mapStore();
    await new VPNDetection({ fetch: api().fetch, cache: { store: store } }).lookup('45.83.91.1');
    assert.equal(store.log.sets[0].ttlMs, HOUR);
});
