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
const CLASS_KEYS = ['provider', 'provider_name', 'confidence', 'last_seen'];
const PROXY_KEYS = [
    'provider', 'provider_name', 'first_seen', 'last_seen', 'hits', 'hits_days_pct', 'providers_num',
];
export const MEMBERS = {
    vpn: { required: ['provider', 'provider_name', 'last_seen'], optional: ['confidence', 'method'] },
    hosting: { required: CLASS_KEYS, optional: [] },
    relay: { required: CLASS_KEYS, optional: [] },
    tor: { required: CLASS_KEYS, optional: [] },
    cdn: { required: CLASS_KEYS, optional: [] },
    resproxy: { required: PROXY_KEYS, optional: [] },
    dcproxy: { required: PROXY_KEYS, optional: [] },
    mobproxy: { required: PROXY_KEYS, optional: [] },
    pubproxy: {
        required: ['entry', 'exit', 'protocols', 'num_ports', 'num_proxies', 'last_seen', 'last_usable'],
        optional: [],
    },
};

// The network and service members, read by the client from 1.6.0: an older
// install drops them, so they join the lists only once it reads them.
export const READS_NETWORK_MEMBERS = needsVersion('1.6.0', 'the network and service members') === false;
const WEB_KEYS = [
    'port', 'tls_ok', 'session_ok', 'status_code', 'server', 'location', 'title', 'cert_subject_cn',
    'cert_subject_o', 'cert_issuer_dn', 'cert_browser_trusted', 'tls_version', 'first_seen', 'last_seen',
];
if (READS_NETWORK_MEMBERS) {
    Object.assign(MEMBERS, {
        carrier: { required: ['name', 'mcc', 'mnc', 'country', 'confidence'], optional: [] },
        satellite: {
            required: ['provider', 'provider_name', 'orbit', 'segment', 'country', 'asn', 'confidence'], optional: [],
        },
        ssh: { required: ['port', 'banner', 'host_key_fp', 'session_ok', 'first_seen', 'last_seen'], optional: [] },
        smtp: { required: ['port', 'banner', 'session_ok', 'first_seen', 'last_seen'], optional: [] },
        dns_resolver: {
            required: ['port', 'recursion_available', 'rcode', 'answer_correct', 'first_seen', 'last_seen'],
            optional: [],
        },
        bittorrent: {
            required: [
                'verified', 'id_matches_ip', 'first_seen', 'last_seen', 'last_reachable', 'days_seen', 'num_ports',
                'peak_num_ports', 'indexer', 'clients',
            ],
            optional: [],
        },
    });
}

const camel = (s) => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());

// Wire name to the property the client maps it onto, which is what lets a test
// say "this field is absent" about both halves at once.
export const RESULT_PROP = { ip: 'ip' };
for (const name of Object.keys(MEMBERS)) {
    RESULT_PROP[`is_${name}`] = flagProp(name);
    RESULT_PROP[name] = detailProp(name);
}
if (READS_NETWORK_MEMBERS) {
    for (const name of ['is_anycast', 'is_web', 'web', 'company', 'hostname', 'abuse']) {
        RESULT_PROP[name] = camel(name);
    }
}

export function flagProp(name) {
    const c = camel(name);
    return `is${c[0].toUpperCase()}${c.slice(1)}`;
}

export function detailProp(name) {
    return camel(name);
}


// The suite runs against whatever the REGISTRY offers, which lags the working
// tree between releases. A method added since the last publish is not a
// failure, so its tests name the version they need and skip until it lands.
export function needsVersion(min, what) {
    const have = triple(INSTALLED_VERSION);
    const want = triple(min);
    for (let i = 0; i < 3; i++) {
        if (have[i] === want[i]) {
            continue;
        }
        if (have[i] > want[i]) {
            return false;
        }
        return `${what} landed in ${min}, and the registry currently offers ${INSTALLED_VERSION}`;
    }
    return false;
}

function triple(version) {
    const parts = version.split(/[-+]/)[0].split('.');
    return [0, 1, 2].map((i) => Number(parts[i]) || 0);
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
        if (!(detailProp(name) in r)) {
            continue;
        }
        // A detail object without its flag would leave a caller reading the
        // object to find out whether the address is flagged at all.
        assert.ok(flag in r, `${name} is served without ${flag}`);
        assertDetail(r, name, MEMBERS[name]);
    }
    if (READS_NETWORK_MEMBERS) {
        assertWeb(r);
    }
}

// A row per port that answered, and an empty list when no web server did.
function assertWeb(r) {
    if ('isWeb' in r) {
        assert.equal(typeof r.isWeb, 'boolean', 'isWeb is present, so it must be a real boolean');
    }
    if (!('web' in r)) {
        return;
    }
    assert.ok('isWeb' in r, 'web is served without isWeb');
    assert.ok(Array.isArray(r.web), 'web must be a list when present');
    assert.equal(r.web.length > 0, r.isWeb, 'web has a row exactly when isWeb is true');
    for (const row of r.web) {
        assert.deepEqual(Object.keys(row).sort(), [...WEB_KEYS].sort(), 'a web row carries exactly its documented keys');
    }
}

function assertDetail(r, name, spec) {
    const detail = r[detailProp(name)];
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
