// A spent trial's or a reached cap's answer ends with a renewed trial or a raised
// cap, so it is cached for a minute at most, in memory and in a store, rather than
// for the client's TTL.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { VPNDetection, VPNDetectionError } from '../dist/index.js';

const HOUR = 60 * 60 * 1000;
const MINUTE = 60 * 1000;

const FLAGS = {
    '45.83.91.1': {},
    '45.83.91.2': { trial_expired: false, cap_reached: false },
    '45.83.91.3': { trial_expired: true },
    '45.83.91.4': { cap_reached: true },
};

// Answers a lookup and a batch with each address's flags, counting requests.
function api() {
    const state = { requests: 0 };
    const answer = (ip) => ({ ip: ip, is_vpn: false, ...FLAGS[ip] });
    const fetch = async (input) => {
        state.requests += 1;
        const path = new URL(input.url).pathname;
        if (path === '/batch') {
            const ips = JSON.parse(await input.text()).ips;
            return Response.json({ results: Object.fromEntries(ips.map((ip) => [ip, answer(ip)])), errors: {} });
        }
        return Response.json(answer(decodeURIComponent(path.slice(1))));
    };
    return { fetch: fetch, state: state };
}

function recordingStore() {
    const sets = new Map();
    return {
        sets: sets,
        get: () => undefined,
        set: (key, _result, ttlMs) => {
            sets.set(key.slice(key.lastIndexOf(':') + 1), ttlMs);
        },
    };
}

const CASES = [
    ['45.83.91.1', HOUR, HOUR],
    ['45.83.91.2', HOUR, HOUR],
    ['45.83.91.3', HOUR, MINUTE],
    ['45.83.91.4', HOUR, MINUTE],
    ['45.83.91.3', 5000, 5000],
    ['45.83.91.4', 5000, 5000],
    ['45.83.91.1', 5000, 5000],
];

for (const how of ['lookup', 'lookupBatch']) {
    test(`${how}: each answer is cached as long as its flags allow`, async () => {
        for (const [ip, ttlMs, want] of CASES) {
            const store = recordingStore();
            const client = new VPNDetection({ fetch: api().fetch, cache: { ttlMs: ttlMs, store: store } });

            if (how === 'lookup') {
                await client.lookup(ip);
            } else {
                await client.lookupBatch([ip, '45.83.91.1']);
            }

            const left = client.cache.getRemainingTTL(ip);
            assert.ok(left <= want && left > want - 1000, `${ip} under ${ttlMs} ms held ${left} ms`);
            assert.equal(store.sets.get(ip), want, `${ip} under ${ttlMs} ms stored`);
        }
    });
}

test('a reduced answer is still cached, so a repeat sends nothing', async () => {
    const server = api();
    const client = new VPNDetection({ fetch: server.fetch });

    await client.lookup('45.83.91.3');
    const again = await client.lookup('45.83.91.3');

    assert.equal(again.trialExpired, true);
    assert.equal(server.state.requests, 1);
});

// lru-cache reads a zero or NaN TTL as none, so a reduced answer would stay for good.
test('a cache TTL or size that is not a whole number from 1 is refused where it is set', () => {
    const refused = [
        ['ttlMs', 0], ['ttlMs', NaN], ['ttlMs', -1], ['ttlMs', 1.5], ['ttlMs', Infinity], ['ttlMs', '1000'],
        ['max', 0], ['max', NaN], ['max', -1], ['max', 1.5], ['max', Infinity], ['max', '10'],
    ];
    for (const [name, value] of refused) {
        assert.throws(() => new VPNDetection({ fetch: api().fetch, cache: { [name]: value } }), (err) => {
            assert.ok(err instanceof VPNDetectionError, `${name} ${String(value)}: wrong error type`);
            assert.equal(err.kind, 'bad_request', `${name} ${String(value)}`);
            assert.match(err.message, new RegExp(`cache\\.${name}`), `${name} ${String(value)}`);
            return true;
        });
    }
    for (const cache of [{ ttlMs: null, max: null }, { ttlMs: 1, max: 1 }]) {
        assert.doesNotThrow(() => new VPNDetection({ fetch: api().fetch, cache: cache }));
    }
});
