// What each call does with a 2xx it cannot read as its answer, how a Retry-After
// is read, and what an API key sends: an unreadable answer is a retried
// server_error carrying its status, never a Result holding nothing, a raw
// TypeError or an answer of the wrong type.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { VPNDetection } from '../dist/index.js';

const IP = '45.83.91.1';
const OTHER = '9.9.9.9';
const ch = (code) => String.fromCharCode(code);

function rawClient(reply, options = {}) {
    const calls = [];
    const fetch = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        calls.push({ url: request.url, auth: request.headers.get('authorization') });
        return reply(request);
    };
    return {
        calls: calls,
        client: new VPNDetection({ apiKey: 'test-key', fetch: fetch, retries: 2, cache: false, ...options }),
    };
}

function body(text, type = 'application/json') {
    return () => new Response(text, { status: 200, headers: { 'content-type': type } });
}

// The body stops part way, as when a proxy drops the connection.
function cutOff() {
    return () => new Response(new ReadableStream({
        start(controller) {
            controller.enqueue(new TextEncoder().encode('{"ip":"45.83.91.1","is_v'));
            controller.error(new TypeError('terminated'));
        },
    }), { status: 200, headers: { 'content-type': 'application/json' } });
}

// Each call, a body with its member of the wrong type, and one missing a member it needs.
const CALLS = {
    lookup: [(c) => c.lookup(IP), `{"ip":"${IP}","is_vpn":"no"}`, `{"ip":"${IP}"}`],
    myIp: [(c) => c.myIp(), '{"ip":1,"is_vpn":false}', '{"is_vpn":false}'],
    myEntitlement: [
        (c) => c.myEntitlement(), '{"org_id":"o","apikey":"x","plan":{},"usage":{}}', '{"org_id":"o"}',
    ],
};

test('a 2xx a call cannot read is a retried server_error carrying its status', async () => {
    for (const [name, [call, wrongType, noMembers]] of Object.entries(CALLS)) {
        const replies = {
            html: body('<html><body>Bad gateway</body></html>', 'text/html'),
            cut: cutOff(),
            empty: body(''),
            null: body('null'),
            array: body('[]'),
            object: body('{}'),
            wrongType: body(wrongType),
            noMembers: body(noMembers),
        };
        // Concurrently, since each sits out the retries' backoff.
        await Promise.all(Object.entries(replies).map(async ([kind, reply]) => {
            const c = rawClient(reply);
            await assert.rejects(() => call(c.client), (err) => {
                assert.equal(err.kind, 'server_error', `${name} ${kind}: ${err.message}`);
                assert.equal(err.status, 200, `${name} ${kind}`);
                return true;
            });
            assert.equal(c.calls.length, 3, `${name} ${kind} is retried`);
        }));
    }
});

test('a batch chunk it cannot read is retried, and fails every address with the status', async () => {
    const replies = {
        html: body('<html><body>Bad gateway</body></html>', 'text/html'),
        cut: cutOff(),
        empty: body(''),
        null: body('null'),
        array: body('[]'),
        object: body('{}'),
        noErrors: body(`{"results":{"${IP}":{"ip":"${IP}","is_vpn":false}}}`),
        wrongType: body('{"results":[],"errors":{}}'),
    };
    await Promise.all(Object.entries(replies).map(async ([kind, reply]) => {
        const c = rawClient(reply);
        const out = await c.client.lookupBatch([IP, OTHER]);
        for (const ip of [IP, OTHER]) {
            assert.equal(out.get(ip).kind, 'server_error', `${kind} ${ip}: ${out.get(ip).message}`);
            assert.equal(out.get(ip).status, 200, `${kind} ${ip}`);
        }
        assert.equal(c.calls.length, 3, `${kind} is retried`);
    }));
});

test('one batch entry it cannot read is that address error alone', async () => {
    for (const entry of [{}, [], 'x', { ip: OTHER }]) {
        for (const map of ['results', 'errors']) {
            const answer = { results: { [IP]: { ip: IP, is_vpn: true } }, errors: {} };
            answer[map][OTHER] = entry;
            const c = rawClient(body(JSON.stringify(answer)));
            const out = await c.client.lookupBatch([IP, OTHER]);
            assert.equal(out.get(IP).isVpn, true, `${map} ${JSON.stringify(entry)}`);
            assert.equal(out.get(OTHER).kind, 'server_error', `${map} ${JSON.stringify(entry)}`);
            assert.equal(out.get(OTHER).status, 200, `${map} ${entry}`);
            assert.equal(c.calls.length, 1, `${map} ${entry} is not retried for one entry`);
        }
    }
});

test('an address named like a member of every object reads its own entry', async () => {
    const names = ['__proto__', 'constructor', 'toString'];
    const errors = names.map((name) => `"${name}":{"status":400,"error":"not a valid IP address"}`).join(',');
    const c = rawClient(body(`{"results":{"${IP}":{"ip":"${IP}","is_vpn":true}},"errors":{${errors}}}`));
    const out = await c.client.lookupBatch([IP, ...names]);
    assert.equal(out.get(IP).isVpn, true);
    for (const name of names) {
        assert.equal(out.get(name).kind, 'bad_request', name);
        assert.equal(out.get(name).status, 400, name);
    }
    assert.equal(c.calls.length, 1);
});

test('a readable answer still comes back', async () => {
    let c = rawClient(body(`{"ip":"${IP}","is_vpn":true}`));
    assert.equal((await c.client.lookup(IP)).isVpn, true);
    const entitlement = {
        org_id: 'o', apikey: { id: 'k', expires: null, allowed_cidrs: [] }, plan: { key: 'max', tier: 'max' },
        usage: {
            requests: 1, quota: 10, hard_limit: null,
            window_start: '2026-10-01T00:00:00Z', window_end: '2026-11-01T00:00:00Z',
        },
    };
    c = rawClient(body(JSON.stringify(entitlement)));
    assert.deepEqual(await c.client.myEntitlement(), entitlement);
    c = rawClient(body(JSON.stringify({
        results: { [IP]: { ip: IP, is_vpn: true } }, errors: { [OTHER]: { status: 429, error: 'spent' } },
    })));
    const out = await c.client.lookupBatch([IP, OTHER]);
    assert.equal(out.get(IP).isVpn, true);
    assert.equal(out.get(OTHER).kind, 'quota_exceeded');
    assert.equal(c.calls.length, 1);
});

test('a served is_bogon reaches the result', async () => {
    for (const served of [true, false]) {
        const c = rawClient(body(`{"ip":"${IP}","is_bogon":${served},"is_vpn":false}`));
        assert.equal((await c.client.lookup(IP)).isBogon, served);
        const batch = rawClient(body(`{"results":{"${IP}":{"ip":"${IP}","is_bogon":${served},"is_vpn":false}},"errors":{}}`));
        assert.equal((await batch.client.lookupBatch([IP])).get(IP).isBogon, served);
    }
    const detailed = rawClient(body(JSON.stringify({
        ip: IP, is_vpn: true, vpn: { provider: 'nordvpn', provider_name: 'NordVPN', last_seen: '2026-11-14' },
    })));
    assert.equal((await detailed.client.lookup(IP)).vpn.provider_name, 'NordVPN');
});

test('a member of the wrong type is a retried server_error carrying its status', async () => {
    const lookup = { ip: IP, is_vpn: true };
    const location = {
        continent: 'EU', continent_name: 'Europe', country: 'DE', country_name: 'Germany',
        timezone: 'Europe/Berlin', currency_code: 'EUR', currency_name: 'Euro', currency_symbol: ch(0x20ac),
        flag_emoji: 'x', flag_unicode: 'x',
    };
    const entitlement = {
        org_id: 'o', apikey: { id: 'a', expires: null, allowed_cidrs: [] }, plan: { key: 'max', tier: 'max' },
        usage: {
            requests: 1, quota: 2, hard_limit: null,
            window_start: '2026-10-01T00:00:00Z', window_end: '2026-11-01T00:00:00Z',
        },
    };
    const look = (c) => c.lookup(IP);
    const ent = (c) => c.myEntitlement();
    const cases = {
        'is_hosting as "yes"': [look, { ...lookup, is_hosting: 'yes' }],
        'a vpn detail of "x"': [look, { ...lookup, vpn: 'x' }],
        'a vpn provider of 1': [look, { ...lookup, vpn: { provider: 1 } }],
        'a vpn provider_name of 1': [look, { ...lookup, vpn: { provider: 'p', provider_name: 1 } }],
        'is_bogon as "no"': [look, { ...lookup, is_bogon: 'no' }],
        'a last_seen of 5': [look, { ...lookup, hosting: { last_seen: 5 } }],
        'dcproxy hits of "3"': [look, { ...lookup, dcproxy: { hits: '3' } }],
        'resproxy hits of 1.5': [look, { ...lookup, resproxy: { hits: 1.5 } }],
        'pubproxy num_ports of "2"': [look, { ...lookup, pubproxy: { num_ports: '2' } }],
        'pubproxy entry of "yes"': [look, { ...lookup, pubproxy: { entry: 'yes' } }],
        'pubproxy protocols of [1]': [look, { ...lookup, pubproxy: { protocols: [1] } }],
        'pubproxy protocols of [null]': [look, { ...lookup, pubproxy: { protocols: [null] } }],
        'a location country of 1': [look, { ...lookup, location: { ...location, country: 1 } }],
        'a location without its members': [look, { ...lookup, location: {} }],
        'an asn of "5"': [look, {
            ...lookup, asn: { asn: '5', name: 'n', domain: 'd', type: 't', prefix: 'p' },
        }],
        'myIp with is_tor as 0': [(c) => c.myIp(), { ...lookup, is_tor: 0 }],
        'requests of "5"': [ent, { ...entitlement, usage: { ...entitlement.usage, requests: '5' } }],
        'a hard_limit of "5"': [ent, { ...entitlement, usage: { ...entitlement.usage, hard_limit: '5' } }],
        'a tier of 1': [ent, { ...entitlement, plan: { key: 'max', tier: 1 } }],
        'allowed_cidrs of [1]': [ent, {
            ...entitlement, apikey: { ...entitlement.apikey, allowed_cidrs: [1] },
        }],
    };
    // Concurrently, since each sits out the retries' backoff.
    await Promise.all(Object.entries(cases).map(async ([name, [call, answer]]) => {
        const c = rawClient(body(JSON.stringify(answer)));
        await assert.rejects(() => call(c.client), (err) => {
            assert.equal(err.kind, 'server_error', `${name}: ${err.message}`);
            assert.equal(err.status, 200, name);
            return true;
        });
        assert.equal(c.calls.length, 3, `${name} is retried`);
    }));
    // A batch entry it cannot read is that address's error alone, unretried.
    const entry = { ...lookup, dcproxy: { hits: '3' } };
    const c = rawClient(body(JSON.stringify({ results: { [IP]: entry }, errors: {} })));
    const out = await c.client.lookupBatch([IP]);
    assert.equal(out.get(IP).kind, 'server_error');
    assert.equal(c.calls.length, 1);
});

// RFC 3339 alone, on a day that exists.
test('a date or date-time that is not RFC 3339 is a retried server_error', async () => {
    const dateTimes = ['2026-10-05', '2026-10-05T10:00:00', '2026-10-05T10:00:00+05', '2026-10-05T10:00Z',
        '2026-10-05T10:00:00+0500', '2026-10-05T10:00:00+05:00:30', '2026-10-05T24:00:00Z',
        '2026-10-05T10:60:00Z', '2026-10-05T10:00:60Z', '2026-02-30T10:00:00Z', '2026-10-05T10:00:00+24:00',
        '2026-10-05T10:00:00+05:60', ' 2026-10-05T10:00:00Z', '2026-10-05T10:00:00Z ', '2026-10-05 10:00:00Z',
        '2026-10-5T10:00:00Z', '+12026-10-05T10:00:00Z', '2026-10-05T10:00:00.Z', '20261005T100000Z', 'x',
        'tomorrow', 'monday', ''];
    const dates = ['2026-10-05T10:00:00', '2026-10-05T10:00:00Z', '2026-02-30', '2026-13-01', '2026-10-5',
        '20261005', '2026-W41-1', ' 2026-10-05', '+12026-10-05', 'x', 'tomorrow', 'monday', ''];
    const lookup = { ip: IP, is_vpn: true };
    const entitlement = {
        org_id: 'o', apikey: { id: 'a', expires: null, allowed_cidrs: [] }, plan: { key: 'max', tier: 'max' },
        usage: {
            requests: 1, quota: 2, hard_limit: null,
            window_start: '2026-10-01T00:00:00Z', window_end: '2026-11-01T00:00:00Z',
        },
    };
    const look = (c) => c.lookup(IP);
    const ent = (c) => c.myEntitlement();
    const cases = [];
    const usage = (member, value) => ({ ...entitlement, usage: { ...entitlement.usage, [member]: value } });
    const expiring = (value) => ({ ...entitlement, apikey: { ...entitlement.apikey, expires: value } });
    for (const value of dateTimes) {
        cases.push([`window_start ${value}`, ent, usage('window_start', value)]);
        cases.push([`window_end ${value}`, ent, usage('window_end', value)]);
        cases.push([`expires ${value}`, ent, expiring(value)]);
    }
    for (const value of dates) {
        cases.push([`vpn last_seen ${value}`, look, { ...lookup, vpn: { last_seen: value } }]);
        cases.push([`hosting last_seen ${value}`, look, { ...lookup, hosting: { last_seen: value } }]);
        cases.push([`dcproxy first_seen ${value}`, look, { ...lookup, dcproxy: { first_seen: value } }]);
        cases.push([`pubproxy last_seen ${value}`, look, { ...lookup, pubproxy: { last_seen: value } }]);
    }
    await Promise.all(cases.map(async ([name, call, served]) => {
        const c = rawClient(body(JSON.stringify(served)), { retries: 1 });
        await assert.rejects(() => call(c.client), (err) => {
            assert.equal(err.kind, 'server_error', `${name}: ${err.message}`);
            assert.equal(err.status, 200, name);
            return true;
        });
        assert.equal(c.calls.length, 2, `${name} is retried`);
    }));
    for (const value of ['2026-10-05T10:00:00Z', '2026-10-05t10:00:00.5z', '2026-10-05T10:00:00-00:00',
        '2026-10-05T10:00:00.123456789+05:30', '2024-02-29T23:59:59+23:59', '0001-01-01T00:00:00Z']) {
        const c = rawClient(body(JSON.stringify(expiring(value))));
        assert.equal((await c.client.myEntitlement()).apikey.expires, value, value);
    }
    for (const value of ['2026-10-05', '2024-02-29', '0099-12-31']) {
        const c = rawClient(body(JSON.stringify({ ...lookup, hosting: { last_seen: value } })));
        assert.equal((await c.client.lookup(IP)).hosting.last_seen, value, value);
    }
});

// The generated types and the pinned spec, read as text: the tables are
// hand-written, so a member or a date the spec adds must fail here until it is
// checked.
const GENERATED = readFileSync(new URL('../src/generated/types.gen.ts', import.meta.url), 'utf8');

function generatedBlock(name) {
    const block = GENERATED.split(`export type ${name} = {\n`)[1];
    assert.ok(block !== undefined, `types.gen.ts has no ${name}`);
    return block.split('\n};')[0];
}

// Each `date` and `date-time` kind is the spec's `format` for that member, and no
// other member carries one, so a date the spec adds is checked before it ships.
test('each date kind is the format the spec names', async () => {
    const shapes = await import('../dist/shapes.js');
    const spec = readFileSync(new URL('../spec/openapi.yaml', import.meta.url), 'utf8');
    const formats = new Map();
    let schema = null;
    let member = null;
    for (const line of spec.split('\n').slice(spec.split('\n').indexOf('components:'))) {
        schema = /^ {4}([A-Za-z][A-Za-z0-9]*):$/.exec(line)?.[1] ?? schema;
        member = /^ {8}([a-z_]+):$/.exec(line)?.[1] ?? member;
        const format = /^ {10}format: (date|date-time)$/.exec(line)?.[1];
        if (format !== undefined) {
            formats.set(`${schema}.${member}`, format);
        }
    }
    const tables = {
        VpnDetail: shapes.VPN_DETAIL_TYPES, ClassDetail: shapes.CLASS_DETAIL_TYPES,
        ProxyDetail: shapes.PROXY_DETAIL_TYPES, PubproxyDetail: shapes.PUBPROXY_DETAIL_TYPES,
        EntitlementApikey: shapes.ENTITLEMENT_APIKEY_TYPES,
        EntitlementUsage: shapes.ENTITLEMENT_USAGE_TYPES, LookupResponse: shapes.LOOKUP_TYPES,
        Location: shapes.LOCATION_TYPES, Asn: shapes.ASN_TYPES, Entitlement: shapes.ENTITLEMENT_TYPES,
    };
    const kinds = new Map();
    for (const [name, table] of Object.entries(tables)) {
        for (const [m, kind] of Object.entries(table)) {
            if (kind === 'date' || kind === 'date-time') {
                kinds.set(`${name}.${m}`, kind);
            }
        }
    }
    const covered = [...formats].filter(([at]) => tables[at.split('.')[0]] !== undefined);
    assert.ok(covered.length >= 8, `found only ${covered.length} dates in the spec's lookup and entitlement`);
    for (const [at, format] of covered) {
        assert.equal(kinds.get(at), format, at);
    }
    assert.equal(kinds.size, covered.length);
});

// The lists are hand-written, so a member the spec makes required, and never null,
// must not be able to go unchecked: read the generated types and compare.
test('each checked member list is every required member of its generated type', async () => {
    const shapes = await import('../dist/shapes.js');
    const required = (name) => [...generatedBlock(name).matchAll(/^ {4}([a-z][a-z0-9_]*): (.*)$/gm)]
        .filter((m) => !/\| null;$/.test(m[2])).map((m) => m[1]).sort();
    assert.deepEqual([...shapes.LOOKUP_MEMBERS].sort(), required('LookupResponse'));
    assert.deepEqual([...shapes.BATCH_MEMBERS].sort(), required('BatchLookupResponse'));
    assert.deepEqual([...shapes.BATCH_ERROR_MEMBERS].sort(), required('BatchLookupError'));
    assert.deepEqual([...shapes.ENTITLEMENT_MEMBERS].sort(), required('Entitlement'));
    assert.deepEqual([...shapes.ENTITLEMENT_APIKEY_MEMBERS].sort(), required('EntitlementApikey'));
    assert.deepEqual([...shapes.ENTITLEMENT_PLAN_MEMBERS].sort(), required('EntitlementPlan'));
    assert.deepEqual([...shapes.ENTITLEMENT_USAGE_MEMBERS].sort(), required('EntitlementUsage'));
    assert.deepEqual([...shapes.LOCATION_MEMBERS].sort(), required('Location'));
    assert.deepEqual([...shapes.ASN_MEMBERS].sort(), required('Asn'));
});

// Each type table names every member of its generated type, optional and nullable
// ones included, so a member the spec adds is typed before it can come back unread.
test('each type table covers every member of its generated type', async () => {
    const shapes = await import('../dist/shapes.js');
    const members = (name) => [...generatedBlock(name).matchAll(/^ {4}([a-z][a-z0-9_]*)\??: /gm)]
        .map((m) => m[1]).sort();
    const tables = {
        LookupResponse: shapes.LOOKUP_TYPES, VpnDetail: shapes.VPN_DETAIL_TYPES,
        ClassDetail: shapes.CLASS_DETAIL_TYPES, ProxyDetail: shapes.PROXY_DETAIL_TYPES,
        PubproxyDetail: shapes.PUBPROXY_DETAIL_TYPES, Location: shapes.LOCATION_TYPES, Asn: shapes.ASN_TYPES,
        BatchLookupError: shapes.BATCH_ERROR_TYPES,
        Entitlement: shapes.ENTITLEMENT_TYPES, EntitlementApikey: shapes.ENTITLEMENT_APIKEY_TYPES,
        EntitlementPlan: shapes.ENTITLEMENT_PLAN_TYPES, EntitlementUsage: shapes.ENTITLEMENT_USAGE_TYPES,
    };
    for (const [name, table] of Object.entries(tables)) {
        assert.deepEqual(Object.keys(table).sort(), members(name), name);
    }
});

// Digits, or one of RFC 9110's three date forms in GMT, and nothing else.
test('a Retry-After is seconds or an HTTP date and nothing else', async () => {
    const at = (offset) => new Date(Date.now() + offset);
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const day = (d) => days[d.getUTCDay()];
    const forms = {
        imf: (d) => d.toUTCString(),
        rfc850: (d) => {
            const [, dd, mon, yyyy, time] = d.toUTCString().split(' ');
            return `${day(d)}, ${dd}-${mon}-${yyyy.slice(2)} ${time} GMT`;
        },
        asctime: (d) => {
            const [wkd, , mon, yyyy, time] = d.toUTCString().split(' ');
            return `${wkd.slice(0, 3)} ${mon} ${String(d.getUTCDate()).padStart(2, ' ')} ${time} ${yyyy}`;
        },
    };
    const throttled = (value) => () => new Response('{"error":"slow down"}', {
        status: 429, headers: { 'content-type': 'application/json', 'retry-after': value() },
    });
    for (const [form, format] of Object.entries(forms)) {
        // Computed when its case runs: a date fixed up front can pass before it is served.
        const c = rawClient(throttled(() => format(at(10_000))), { retries: 0 });
        await assert.rejects(() => c.client.lookup(IP), (err) => {
            assert.equal(err.kind, 'rate_limited', form);
            const seconds = err.retryAfterSeconds;
            assert.ok(seconds >= 8 && seconds <= 11, `${form}: ${seconds}`);
            return true;
        });
    }
    for (const value of ['7', '0']) {
        const c = rawClient(throttled(() => value), { retries: 0 });
        await assert.rejects(() => c.client.lookup(IP), (err) => {
            assert.equal(err.kind, 'rate_limited', value);
            assert.equal(err.retryAfterSeconds, Number(value));
            return true;
        });
    }
    const spent = [
        '+1', '-1', 'x', 'tomorrow', '1e400', '0x10', '0b11', '1_0', '1e3', '1.5', '2099-01-01',
        '2099-01-01T00:00:00', 'Jan 1 2099', 'Sun, 31 Nov 2099 08:49:37 GMT', 'Fri, 01 Jan 2099 00:00:00 PST',
        'Fri, 01 Jan 2099 00:00:00 +0500', 'Fri, 01 Jan 2099 24:00:00 GMT', 'Xyz, 01 Jan 2099 00:00:00 GMT',
    ];
    for (const value of spent) {
        const c = rawClient(throttled(() => value));
        await assert.rejects(() => c.client.lookup(IP), (err) => {
            assert.equal(err.kind, 'quota_exceeded', value);
            return true;
        });
        assert.equal(c.calls.length, 1, value);
    }
});

test('the key goes out trimmed, blanks are no key, and a control character is refused', async () => {
    const answer = body(`{"ip":"${IP}","is_vpn":false}`);
    for (const [key, sent] of [['', null], [' ', null], ['\t', null], ['  k  ', 'Bearer k'], [null, null]]) {
        const c = rawClient(answer, { apiKey: key });
        await c.client.lookup(IP);
        assert.equal(c.calls[0].auth, sent, JSON.stringify(key));
    }
    for (const key of ['k\r\nX-Injected: 1', `k${ch(0)}`, `k${ch(0x7f)}`, 'k\nx']) {
        assert.throws(() => new VPNDetection({ apiKey: key }),
            (err) => err.kind === 'bad_request', JSON.stringify(key));
    }
    assert.throws(() => new VPNDetection({ apiKey: 5 }), (err) => err.kind === 'bad_request');
    // fetch refuses a header character past U+00FF, so such a key would fail every
    // call as a retried network error with nothing sent.
    for (const key of [`k${ch(0x4e2d)}`, `k${ch(0x100)}`]) {
        assert.throws(() => new VPNDetection({ apiKey: key }),
            (err) => err.kind === 'bad_request', JSON.stringify(key));
    }
    // A Latin-1 key goes out as its bytes, and is answered as any wrong key is.
    const c = rawClient(answer, { apiKey: `k${ch(0xe9)}` });
    await c.client.lookup(IP);
    assert.equal(c.calls[0].auth, `Bearer k${ch(0xe9)}`);
});

// p-retry checks the count only inside the call, so a negative, NaN or
// non-number would fail every call as `network` with p-retry's own message, and
// a bogon would answer any value.
test('a retry count that is not a whole number from 0 is refused where it is set', async () => {
    const answer = body(`{"ip":"${IP}","is_vpn":false}`);
    for (const retries of [-1, 1.5, NaN, -Infinity, '2']) {
        const name = String(retries);
        assert.throws(() => new VPNDetection({ retries: retries }), (err) => err.kind === 'bad_request', name);
        const c = rawClient(answer);
        for (const [call, run] of [
            ['lookup', () => c.client.lookup(IP, { retries: retries })],
            ['a bogon', () => c.client.lookup('10.0.0.1', { retries: retries })],
            ['myIp', () => c.client.myIp({ retries: retries })],
            ['myEntitlement', () => c.client.myEntitlement({ retries: retries })],
            ['lookupBatch', () => c.client.lookupBatch(['10.0.0.1'], { retries: retries })],
        ]) {
            await assert.rejects(run, (err) => err.kind === 'bad_request', `${call}, ${name}`);
        }
        assert.equal(c.calls.length, 0, name);
    }
    for (const retries of [0, 3, Infinity, null]) {
        const c = rawClient(answer, { retries: retries });
        await c.client.lookup(IP, { retries: retries });
    }
});
