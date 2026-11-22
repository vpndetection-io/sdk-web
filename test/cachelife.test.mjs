// A spent trial's or a reached cap's answer ends with a renewed trial or a raised
// cap, so it is cached for a minute at most, in memory and in a store, rather than
// for the client's TTL.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { VPNDetection } from '../dist/index.js';

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
