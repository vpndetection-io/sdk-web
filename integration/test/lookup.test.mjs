// The published package looking addresses up against the staging API.
//
// Nothing here pins a field COUNT. The tiers are asserted as a RELATION -
// each one serves a superset of the tier below it - so a pricing change stays a
// pricing change instead of arriving as a red build. What a served answer must
// satisfy on every tier: `ip` and `is_vpn` always; a present flag is a real
// boolean; a field a higher tier serves is ABSENT on a lower one rather than
// false; a populated detail object carries its documented keys; an empty one
// means its flag is false.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { VPNDetection, VPNDetectionError, isBogon } from 'vpndetection-web';

import {
    INSTALLED_VERSION, MEMBERS, PROBE, RESULT_PROP, STAGING, answerFor, assertServedByTier,
    assertShape, clientFor, flagProp,
} from '../lib/staging.mjs';
import { RUNGS, UNAUTH_RUNG, observableRungs, skipFor } from '../lib/tiers.mjs';

// The ladder needs two rungs to say anything. The unauthenticated one is always
// there, so this only fires when no tier secret at all is configured.
const LADDER = observableRungs().length > 1
    ? false
    : 'no tier secret is set, so there is no ladder to compare';

test('a lookup without a key answers ip and is_vpn at the least', async () => {
    const fixture = await answerFor(UNAUTH_RUNG);

    assert.equal(fixture.result.raw.ip, PROBE);
    assert.equal(typeof fixture.result.raw.is_vpn, 'boolean');
    assert.equal(typeof fixture.result.isVpn, 'boolean');
    assertServedByTier(fixture);
    console.log(`testing vpndetection-web@${INSTALLED_VERSION} against ${STAGING}`);
});

// What a page with no key asks first: whether its own visitor is on a VPN.
test('an unauthenticated myIp answers for the address calling', async () => {
    const sent = [];
    const result = await clientFor(UNAUTH_RUNG, (fact) => sent.push(fact)).myIp();

    assert.deepEqual(sent.map((fact) => fact.path), ['/myip']);
    assert.equal(result.isBogon, false);
    assertShape(result);
});

for (const rung of RUNGS.filter((r) => r.secret !== null)) {
    test(`a ${rung.tier} key reaches the wire and its answer keeps the shape`,
        { skip: skipFor(rung) }, async () => {
            assertServedByTier(await answerFor(rung));
        });

    // Every tier's key belongs to an org on that plan, or the ladder below compares
    // one plan with itself.
    test(`a ${rung.tier} key's entitlement names its plan`, { skip: skipFor(rung) }, async () => {
        const facts = [];
        const entitlement = await clientFor(rung, (fact) => facts.push(fact)).myEntitlement();

        assert.ok(facts.length > 0 && facts.every((fact) => fact.carriedKey), 'the key never reached the wire');
        assert.equal(entitlement.plan.tier, rung.tier);
        assert.ok(Number.isInteger(entitlement.usage.requests), 'usage.requests is not a whole number');
    });
}

test('each tier serves a superset of the tier below', { skip: LADDER }, async () => {
    let below = null;
    for (const rung of observableRungs()) {
        const fixture = await answerFor(rung);
        const fields = new Set(Object.keys(fixture.result.raw));
        console.log(`${rung.tier}: ${fields.size} fields`);
        if (below !== null) {
            for (const field of below.fields) {
                assert.ok(fields.has(field), `${rung.tier} drops ${field}, which ${below.tier} serves`);
            }
            // Without this a suite in which every key resolved to the same plan
            // would pass: identical sets satisfy containment in both directions.
            if (rung.widens) {
                assert.ok(
                    fields.size > below.fields.size,
                    `${rung.tier} answers no more fields than ${below.tier}`,
                );
            }
        }
        below = { tier: rung.tier, fields: fields };
    }
});

test('a field a higher tier serves is absent on a lower one, never false', { skip: LADDER }, async () => {
    const fixtures = [];
    for (const rung of observableRungs()) {
        fixtures.push(await answerFor(rung));
    }

    for (const { rung, result } of fixtures) {
        // The mapper copies on key PRESENCE, not on truthiness, so a plan that
        // includes a flag and answers `false` must keep it.
        for (const field of Object.keys(result.raw)) {
            const prop = RESULT_PROP[field];
            if (prop !== undefined) {
                assert.ok(prop in result, `${rung.tier} serves ${field} and the client dropped it`);
            }
        }
    }

    for (let i = 0; i < fixtures.length - 1; i++) {
        const lower = fixtures[i];
        const higher = new Set(fixtures.slice(i + 1).flatMap((f) => Object.keys(f.result.raw)));
        for (const field of higher) {
            const prop = RESULT_PROP[field];
            if (field in lower.result.raw || prop === undefined) {
                continue;
            }
            assert.ok(
                !(prop in lower.result),
                `${field} is not in the ${lower.rung.tier} plan, so ${prop} must not exist on the result`,
            );
            assert.equal(
                lower.result[prop], undefined,
                `${field} is not in the ${lower.rung.tier} plan, so ${prop} must not read as anything`,
            );
        }
    }
});

test('a bogon is answered without touching the network', async () => {
    const offline = new VPNDetection({
        baseUrl: STAGING,
        fetch: () => {
            throw new Error('the bogon path reached the network');
        },
    });

    const r = await offline.lookup('10.0.0.1');

    assert.equal(r.isBogon, true);
    assert.equal(r.isVpn, false);
    assert.equal(isBogon('10.0.0.1'), true, 'the standalone export must agree');
    for (const name of Object.keys(MEMBERS)) {
        assert.equal(r[flagProp(name)], false, `${flagProp(name)} must be present and false on a bogon`);
        assert.deepEqual(r[name], {}, `${name} must be present and empty on a bogon`);
    }
});

test('a batch without a key is refused as unauthorized, once, and its bogon still answered', async () => {
    const sent = [];
    const keyless = clientFor(UNAUTH_RUNG, (fact) => sent.push(fact));

    const got = await keyless.lookupBatch([PROBE, '10.0.0.1']);

    assert.equal(got.get('10.0.0.1').isBogon, true);
    const refused = got.get(PROBE);
    assert.ok(refused instanceof VPNDetectionError, 'a batch without a key must fail');
    assert.equal(refused.kind, 'unauthorized');
    assert.equal(refused.status, 401);
    assert.equal(refused.retryable, false);
    assert.deepEqual(sent.map((fact) => fact.path), ['/batch'], 'one request, never retried');
});

const FREE_RUNG = RUNGS.find((rung) => rung.tier === 'free');

test('a batch collapses duplicates and keeps bogons off the wire', { skip: skipFor(FREE_RUNG) }, async () => {
    // A batch needs a key, and the free one is the cheapest that has it. Asserted
    // per request rather than on a count, so a retry against a wobbling staging
    // cannot read as a failure to deduplicate.
    const sent = [];
    const counting = clientFor(FREE_RUNG, (fact) => sent.push(fact));

    const got = await counting.lookupBatch([PROBE, '8.8.8.8', PROBE, '10.0.0.1', '8.8.8.8']);

    assert.deepEqual([...got.keys()], [PROBE, '8.8.8.8', '10.0.0.1']);
    assert.ok(sent.length > 0, 'the batch reached nothing');
    for (const fact of sent) {
        assert.ok(fact.carriedKey, 'the free key reached the wire');
        assert.equal(fact.path, '/batch', 'one POST /batch per chunk, never a lookup per address');
        assert.deepEqual([...fact.ips].sort(), [PROBE, '8.8.8.8'].sort(), 'what the chunk carried');
    }
    assert.equal(got.get('10.0.0.1').isBogon, true);
    for (const ip of [PROBE, '8.8.8.8']) {
        assert.ok(!(got.get(ip) instanceof Error), `${ip} failed`);
        assertShape(got.get(ip));
    }
});

// A page reload or an extension's worker restart is a new client over the same
// store: the published package answers it from the store with no request.
test('a store keeps a served answer for the next client', async () => {
    const entries = new Map();
    const store = {
        get: (key) => entries.get(key),
        set: (key, result) => {
            entries.set(key, result);
        },
    };
    const sent = [];
    const first = new VPNDetection({
        baseUrl: STAGING,
        cache: { store: store },
        fetch: (...args) => {
            sent.push(args);
            return fetch(...args);
        },
    });
    await first.lookup(PROBE);
    assert.equal(sent.length, 1);
    assert.equal(entries.size, 1);

    const second = new VPNDetection({
        baseUrl: STAGING,
        cache: { store: store },
        fetch: () => {
            throw new Error('the stored answer reached the network');
        },
    });
    assert.equal((await second.lookup(PROBE)).ip, PROBE);
});
