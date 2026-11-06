// The staging fixtures the test files share: one client per tier, one lookup
// per tier, and the shape rules that hold whatever the plan.
//
// The package runs here under Node, which has fetch and Web Crypto as a browser
// does; what only a browser can show is the repo's own browser test.

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { VPNDetection } from 'vpndetection-web';

import { keyFor } from './tiers.mjs';

export const STAGING = 'https://api-staging.vpndetection.io';

// A stable VPN address, and the one the README teaches.
export const PROBE = '45.83.91.1';

const require = createRequire(import.meta.url);
export const INSTALLED_VERSION = require('vpndetection-web/package.json').version;

// One entry per dataset the API answers about. `required` is what a POPULATED
// detail object carries on every tier; `optional` is the max-only remainder,
// which is absent rather than empty on a lower plan.
const CLASS_KEYS = ['provider', 'confidence', 'last_seen'];
const PROXY_KEYS = ['provider', 'first_seen', 'last_seen', 'hits', 'hits_days_pct', 'providers_num'];
export const MEMBERS = {
    vpn: { required: ['provider', 'last_seen'], optional: ['confidence', 'method'] },
    hosting: { required: CLASS_KEYS, optional: [] },
    relay: { required: CLASS_KEYS, optional: [] },
    tor: { required: CLASS_KEYS, optional: [] },
    cdn: { required: CLASS_KEYS, optional: [] },
    resproxy: { required: PROXY_KEYS, optional: [] },
    dcproxy: { required: PROXY_KEYS, optional: [] },
    mobproxy: { required: PROXY_KEYS, optional: [] },
};

// Wire name to the property the client maps it onto, which is what lets a test
// say "this field is absent" about both halves at once.
export const RESULT_PROP = { ip: 'ip' };
for (const name of Object.keys(MEMBERS)) {
    RESULT_PROP[`is_${name}`] = flagProp(name);
    RESULT_PROP[name] = name;
}

export function flagProp(name) {
    return `is${name[0].toUpperCase()}${name.slice(1)}`;
}

export function clientFor(rung, onRequest = () => {}) {
    const key = keyFor(rung);
    return new VPNDetection({
        baseUrl: STAGING,
        ...(key === '' ? {} : { apiKey: key }),
        fetch: async (...args) => {
            onRequest({ ...requestFacts(args, key), ips: await batchAddresses(args) });
            return fetch(...args);
        },
    });
}

// The addresses a POST carried, read off a CLONE so the request still sends its
// body; undefined for anything else. Addresses are the one part of a body worth
// remembering, and they are not a secret.
async function batchAddresses(args) {
    const input = args[0];
    if (typeof input === 'string' || input.method !== 'POST') {
        return undefined;
    }
    return JSON.parse(await input.clone().text()).ips;
}

/**
 * What a test is allowed to remember about a request it made.
 *
 * Only derived facts leave here. An assertion that fails prints its operands,
 * so holding on to the Request itself is how a key ends up in a public CI log:
 * whether the key was carried is a boolean, and the caller never sees the key.
 */
export function requestFacts(args, key) {
    const input = args[0];
    const url = typeof input === 'string' ? input : (input.url ?? String(input));
    const headers = input?.headers ?? new Headers(args[1]?.headers ?? {});
    const carriedKey = key !== ''
        && (url.includes(key) || [...headers.values()].some((v) => v.includes(key)));
    const parsed = new URL(url);
    return { origin: parsed.origin, path: parsed.pathname, carriedKey: carriedKey };
}

// One lookup per tier for the whole file. The client caches, so a second reader
// of the same tier costs no request at all.
const answers = new Map();

export function answerFor(rung) {
    let pending = answers.get(rung.tier);
    if (pending === undefined) {
        pending = lookupOnce(rung);
        answers.set(rung.tier, pending);
    }
    return pending;
}

async function lookupOnce(rung) {
    const facts = [];
    const client = clientFor(rung, (fact) => facts.push(fact));
    const result = await client.lookup(PROBE);
    return {
        rung: rung,
        result: result,
        carriedKey: facts.some((fact) => fact.carriedKey),
    };
}

export function assertServedByTier(fixture) {
    assert.equal(fixture.result.ip, PROBE);
    assert.equal(fixture.result.isBogon, false, 'a served answer is not a local one');
    if (fixture.rung.secret !== null) {
        // Without this the tier is indistinguishable from an unauthenticated
        // one, and every comparison the ladder makes against it is vacuous.
        assert.ok(fixture.carriedKey, 'the key never reached the wire');
    }
    assertShape(fixture.result);
}

// Holds on every plan: presence is the plan, the value is the answer.
export function assertShape(r) {
    assert.equal(typeof r.ip, 'string');
    assert.equal(typeof r.isVpn, 'boolean', 'is_vpn is on every plan');

    for (const name of Object.keys(MEMBERS)) {
        const flag = flagProp(name);
        if (flag in r) {
            assert.equal(typeof r[flag], 'boolean', `${flag} is present, so it must be a real boolean`);
        }
        if (!(name in r)) {
            continue;
        }
        // A detail object without its flag would leave a caller reading the
        // object to find out whether the address is flagged at all.
        assert.ok(flag in r, `${name} is served without ${flag}`);
        assertDetail(r, name, MEMBERS[name]);
    }
}

function assertDetail(r, name, spec) {
    const detail = r[name];
    assert.equal(typeof detail, 'object', `${name} must be an object when present`);
    const keys = Object.keys(detail);
    if (keys.length === 0) {
        assert.equal(r[flagProp(name)], false, `${name} is empty, so ${flagProp(name)} must be false`);
        return;
    }
    for (const key of spec.required) {
        assert.ok(key in detail, `${name} is populated but carries no ${key}`);
    }
    for (const key of keys) {
        const known = spec.required.includes(key) || spec.optional.includes(key);
        assert.ok(known, `${name}.${key} is not a documented key of this detail object`);
    }
}
