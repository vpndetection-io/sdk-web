// The OAuth accessor against the corpus's oauth section, oauth.deferred's code-flow
// vectors included. This library has no device flow and no registration, so their
// cases are left out by operation. Runs against dist/, which is what ships.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
    OauthAccessDeniedError, OauthError, OauthExpiredTokenError, VPNDetection, VPNDetectionError,
} from '../dist/index.js';

const corpus = JSON.parse(readFileSync(new URL('../testdata/testdata.json', import.meta.url), 'utf8')).oauth;

const BASE_URL = 'https://api.example.test';

// The operations this client has, and the corpus's cases for them.
const OPERATIONS = ['metadata', 'exchangeAuthorizationCode', 'exchangeRefreshToken', 'revoke'];
const ours = (cases) => cases.filter((c) => OPERATIONS.includes(c.operation));

// Past this many requests, a loop under test fails its test: one that never ends
// would otherwise hang it while memory grows.
const LOOP_BOUND = 16;

// Satisfies every operation's required members at once.
const EVERY_REQUIRED_MEMBER = {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth/authorize`,
    token_endpoint: `${BASE_URL}/oauth/token`,
    access_token: 'mo_at_x',
    token_type: 'Bearer',
    expires_in: 3600,
};

// Each exchange the corpus's token answers and refusals are served to: both post
// to the token endpoint and read its answer the same way.
const EXCHANGES = {
    exchangeRefreshToken: (oauth) => oauth.exchangeRefreshToken('vpndetection-cli', 'mo_rt_x'),
    exchangeAuthorizationCode: (oauth) => oauth.exchangeAuthorizationCode(
        'example-client', 'mo_ac_x', 'v'.repeat(43), 'http://127.0.0.1:8765/callback',
    ),
};

test('the corpus still names every operation this client has', () => {
    const named = new Set([...corpus.forms.cases, ...corpus.deferred.forms, ...corpus.retries.cases,
        ...corpus.deferred.retries].map((c) => c.operation));
    for (const operation of OPERATIONS.filter((o) => o !== 'metadata')) {
        assert.ok(named.has(operation), `the corpus has no case for ${operation}`);
    }
});

test('no OAuth request carries the API key', async () => {
    const { apiKey, forbiddenHeaders, forbiddenQuery } = corpus.noCredential;
    const stub = oauthStub([{ status: 200, body: EVERY_REQUIRED_MEMBER }]);
    const client = oauthClient(stub, { apiKey: apiKey });

    await client.oauth.metadata();
    await client.oauth.exchangeRefreshToken('vpndetection-cli', 'mo_rt_x');
    await client.oauth.exchangeAuthorizationCode(
        'vpndetection-cli', 'mo_ac_x', 'v'.repeat(43), 'http://127.0.0.1/cb',
    );
    await client.oauth.revoke('vpndetection-cli', 'mo_rt_x');

    assert.equal(stub.requests.length, 4);
    const url = client.oauth.authorizationUrl('vpndetection-cli', 'http://127.0.0.1/cb', 'c'.repeat(43));
    assert.equal(url.includes(apiKey), false, 'the authorization URL carried the API key');
    for (const req of stub.requests) {
        const label = `${req.method} ${req.path}`;
        for (const name of forbiddenHeaders) {
            assert.equal(req.headers.get(name), null, `${label} carried ${name}`);
        }
        for (const name of forbiddenQuery) {
            assert.equal(req.query.has(name), false, `${label} carried the ${name} query parameter`);
        }
        const leaked = req.url.includes(apiKey) || req.body.includes(apiKey)
            || [...req.headers.values()].some((value) => value.includes(apiKey));
        assert.equal(leaked, false, `${label} carried the API key`);
    }
});

// Keyless, because nothing about these operations needs a key. Every call also
// passes a timeoutMs, so an exact field match proves it stays off the wire.
test('each operation requests its endpoint with exactly its form fields', async (t) => {
    await t.test('metadata, on a base URL with a trailing slash', async () => {
        const stub = oauthStub([{ status: 200, body: EVERY_REQUIRED_MEMBER }]);
        await oauthClient(stub, { baseUrl: `${BASE_URL}/` }).oauth.metadata({ timeoutMs: 5000 });

        assert.equal(stub.requests.length, 1);
        assertEndpoint(stub.requests[0], corpus.endpoints.metadata);
        assert.equal(stub.requests[0].url, `${BASE_URL}${corpus.endpoints.metadata.path}`);
    });
    const cases = ours([...corpus.forms.cases, ...corpus.deferred.forms]);
    assert.ok(cases.length >= 3, `only ${cases.length} form cases apply`);
    for (const c of cases) {
        await t.test(c.name, async () => {
            const stub = oauthStub([{ status: 200, body: EVERY_REQUIRED_MEMBER }]);
            await callOauth(oauthClient(stub), c.operation, c.args, { timeoutMs: 5000 });

            assert.equal(stub.requests.length, 1);
            const req = stub.requests[0];
            assertEndpoint(req, corpus.endpoints[c.endpoint]);
            const type = req.headers.get('content-type') ?? '';
            assert.ok(type.startsWith(corpus.forms.contentType), `sent as ${type}`);
            assert.deepEqual(formFields(req.body), c.fields);
        });
    }
});

test('a 2xx decodes on presence: absent stays absent, an empty scope stays present', async (t) => {
    for (const c of corpus.responses.metadata) {
        await t.test(`metadata: ${c.name}`, async () => {
            assertDecoded(await oauthClient(oauthStub([c])).oauth.metadata(), c.expect);
        });
    }
    for (const [exchange, call] of Object.entries(EXCHANGES)) {
        for (const c of corpus.responses.token) {
            await t.test(`${exchange}: ${c.name}`, async () => {
                assertDecoded(await call(oauthClient(oauthStub([c])).oauth), c.expect);
            });
        }
    }
    for (const c of corpus.responses.revoke) {
        await t.test(`revoke: ${c.name}`, async () => {
            const stub = oauthStub([c]);
            assert.equal(await oauthClient(stub).oauth.revoke('vpndetection-cli', 'mo_rt_x'), undefined);
            assert.equal(stub.requests.length, 1);
        });
    }
});

test('a 2xx that lacks a required member or does not parse is the ordinary error', async (t) => {
    const cases = {
        'missing access_token': { status: 200, body: { token_type: 'Bearer', expires_in: 3600 } },
        'expires_in as a string': {
            status: 200, body: { access_token: 'mo_at_x', token_type: 'Bearer', expires_in: '3600' },
        },
        'expires_in of 1.5': {
            status: 200, body: { access_token: 'mo_at_x', token_type: 'Bearer', expires_in: 1.5 },
        },
        'not JSON': { status: 200, rawBody: '<html>' },
    };
    for (const [exchange, call] of Object.entries(EXCHANGES)) {
        for (const [name, reply] of Object.entries(cases)) {
            await t.test(`${exchange}: ${name}`, async () => {
                const stub = oauthStub([reply]);
                const err = await settle(call(oauthClient(stub).oauth), stub.bound);
                assertOutcome(err, { type: 'client', kind: 'server_error', status: reply.status }, name);
                assert.equal(stub.requests.length, 1, 'an exchange is never retried');
            });
        }
    }
});

// No corpus case: every response there decodes. One member left out per case,
// since a body missing two at once lets a defaulting decoder survive.
test('an answer missing any one required member is the ordinary error', async (t) => {
    const required = {
        metadata: ['issuer', 'authorization_endpoint', 'token_endpoint'],
        exchangeRefreshToken: ['access_token', 'token_type', 'expires_in'],
        exchangeAuthorizationCode: ['access_token', 'token_type', 'expires_in'],
    };
    const args = {
        clientId: 'vpndetection-cli', refreshToken: 'mo_rt_x', code: 'mo_ac_x', codeVerifier: 'v'.repeat(43),
        redirectUri: 'http://127.0.0.1/cb',
    };
    for (const [operation, members] of Object.entries(required)) {
        for (const member of members) {
            await t.test(`${operation}: ${member}`, async () => {
                const body = { ...EVERY_REQUIRED_MEMBER };
                delete body[member];
                const stub = oauthStub([{ status: 200, body: body }]);
                const call = callOauth(oauthClient(stub, { retries: 0 }), operation, args);
                const err = await settle(call, stub.bound);
                assertOutcome(err, { type: 'client', kind: 'server_error', status: 200 }, member);
            });
        }
    }
});

test('a failed answer is an OAuth refusal only when it is one', async (t) => {
    for (const [exchange, call] of Object.entries(EXCHANGES)) {
        for (const c of corpus.errors.cases) {
            await t.test(`${exchange}: ${c.name}`, async () => {
                const stub = oauthStub([c]);
                const err = await settle(call(oauthClient(stub).oauth), stub.bound);
                assertOutcome(err, c.expect, c.name);
                assert.equal(stub.requests.length, 1, 'an exchange is never retried');
            });
        }
    }
});

test('only what consumes nothing is retried, and never an OAuth refusal', async (t) => {
    const cases = ours([...corpus.retries.cases, ...corpus.deferred.retries]);
    assert.ok(cases.length >= 4, `only ${cases.length} retry cases apply`);
    for (const c of cases) {
        await t.test(c.name, async () => {
            const stub = oauthStub(c.responses);
            const outcome = await settle(callOauth(oauthClient(stub), c.operation, c.args), stub.bound);

            assert.equal(stub.requests.length, c.expect.requests, 'requests sent');
            if (c.expect.outcome === 'ok') {
                assertNotError(outcome);
                return;
            }
            assertOutcome(outcome, { ...c.expect, type: c.expect.outcome }, c.name);
        });
    }
    // The corpus pins this on device authorization, which this client lacks: the
    // two operations here that do retry must not retry a refusal either.
    const refusal = { status: 400, body: { error: 'slow_down', error_description: 'too many requests' } };
    for (const operation of ['metadata', 'revoke']) {
        await t.test(`${operation} does not retry an OAuth refusal`, async () => {
            const stub = oauthStub([refusal]);
            const args = { clientId: 'vpndetection-cli', token: 'mo_rt_x' };
            const outcome = await settle(callOauth(oauthClient(stub), operation, args), stub.bound);
            assert.equal(stub.requests.length, 1, 'requests sent');
            assertOutcome(outcome, { type: 'oauth', errorCode: 'slow_down', retryable: false }, operation);
        });
    }
});

test('an authorization URL is built exactly as the corpus spells it, with no request', async (t) => {
    for (const c of corpus.deferred.authorizationUrl) {
        await t.test(c.name, async () => {
            const stub = oauthStub([{ status: 200, body: EVERY_REQUIRED_MEMBER }]);
            const url = oauthClient(stub, { baseUrl: c.baseUrl }).oauth.authorizationUrl(
                c.clientId, c.redirectUri, c.codeChallenge,
                { scope: c.scope, state: c.state, resource: c.resource },
            );
            assert.equal(url, c.expect);
            assert.equal(stub.requests.length, 0, 'requests sent');
        });
    }
    await t.test('an option given empty is left out, and a required value never is', () => {
        const oauth = new VPNDetection({ baseUrl: BASE_URL }).oauth;
        const required = corpus.deferred.authorizationUrl[0];
        assert.equal(
            oauth.authorizationUrl(required.clientId, required.redirectUri, required.codeChallenge,
                { scope: '', state: '', resource: '' }),
            required.expect.replace(required.baseUrl, BASE_URL),
        );
        assert.throws(() => oauth.authorizationUrl('', required.redirectUri, required.codeChallenge),
            (err) => err instanceof VPNDetectionError && err.kind === 'bad_request');
        const loneSurrogate = String.fromCharCode(0xd800);
        assert.throws(() => oauth.authorizationUrl(required.clientId, required.redirectUri, loneSurrogate),
            (err) => err instanceof VPNDetectionError && err.kind === 'bad_request');
    });
});

// Async here, as Web Crypto's digest is.
test('a PKCE pair is fresh, and its challenge is the S256 one', async () => {
    const { pkce } = corpus.deferred;
    const oauth = new VPNDetection().oauth;
    const challenge = oauth.pkceChallenge(pkce.verifier);
    assert.ok(challenge instanceof Promise, 'pkceChallenge answers a promise');
    assert.equal(await challenge, pkce.challenge);
    const first = await oauth.createPkce();
    assert.match(first.verifier, new RegExp(pkce.generatedVerifierPattern));
    assert.equal(first.challenge, await oauth.pkceChallenge(first.verifier));
    assert.equal(first.method, pkce.method);
    assert.notEqual((await oauth.createPkce()).verifier, first.verifier, 'two pairs share a verifier');
    await assert.rejects(oauth.pkceChallenge(5),
        (err) => err instanceof VPNDetectionError && err.kind === 'bad_request');
});

// A page served over plain http gets crypto.getRandomValues but no crypto.subtle,
// so the two say what is missing rather than failing with a TypeError.
test('PKCE refuses a context without Web Crypto as bad_request', async (t) => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const real = globalThis.crypto;
    const insecure = { getRandomValues: (bytes) => real.getRandomValues(bytes) };
    Object.defineProperty(globalThis, 'crypto', { value: insecure, configurable: true, writable: true });
    t.after(() => {
        Object.defineProperty(globalThis, 'crypto', original);
    });
    const oauth = new VPNDetection().oauth;
    for (const call of [() => oauth.createPkce(), () => oauth.pkceChallenge('verifier')]) {
        const pending = call();
        assert.ok(pending instanceof Promise, 'refused as a rejection, not a throw');
        await assert.rejects(pending, (err) => {
            assert.ok(err instanceof VPNDetectionError);
            assert.equal(err.kind, 'bad_request');
            assert.match(err.message, /Web Crypto/);
            return true;
        });
    }
});

test("the client's timeoutMs bounds every OAuth request", async () => {
    const client = new VPNDetection({ retries: 0, timeoutMs: 80, fetch: () => new Promise(() => {}) });
    const calls = {
        'metadata': () => client.oauth.metadata(),
        'exchangeAuthorizationCode': () => client.oauth.exchangeAuthorizationCode(
            'vpndetection-cli', 'mo_ac_x', 'v'.repeat(43), 'http://127.0.0.1/cb',
        ),
        'exchangeRefreshToken': () => client.oauth.exchangeRefreshToken('vpndetection-cli', 'mo_rt_x'),
        'revoke': () => client.oauth.revoke('vpndetection-cli', 'mo_rt_x'),
    };
    for (const [name, call] of Object.entries(calls)) {
        await assert.rejects(call, (err) => {
            assertOutcome(err, { type: 'client', kind: 'network', retryable: true }, name);
            assert.match(err.message, /timed out after 80ms/, name);
            return true;
        });
    }
});

function oauthClient(stub, options = {}) {
    return new VPNDetection({ baseUrl: BASE_URL, fetch: stub.fetch, ...options });
}

// Answers in order, repeating the last reply, and records what left the client.
// Past `limit` requests it trips the bound rather than answering.
function oauthStub(replies, limit = LOOP_BOUND, bound = loopBound()) {
    const requests = [];
    const fetchFn = async (request) => {
        if (requests.length === limit) {
            return bound.trip(`sent more than ${limit} request(s)`);
        }
        const url = new URL(request.url);
        requests.push({
            method: request.method,
            path: url.pathname,
            query: url.searchParams,
            url: request.url,
            headers: request.headers,
            body: await request.text(),
        });
        const reply = replies[Math.min(requests.length, replies.length) - 1];
        return new Response(reply.rawBody ?? JSON.stringify(reply.body), {
            status: reply.status, headers: { 'content-type': 'application/json' },
        });
    };
    return { fetch: fetchFn, requests: requests, bound: bound };
}

// Ends a test whose code under test does not end: `tripped` rejects, and the
// loop is handed a promise that never settles, so it stops instead of spinning.
function loopBound() {
    const bound = {};
    bound.tripped = new Promise((_, reject) => {
        bound.trip = (what) => {
            reject(new Error(`${what}: the call under test does not end`));
            return new Promise(() => {});
        };
    });
    bound.tripped.catch(() => {});
    return bound;
}

// The call's value, or the error it rejected with; a tripped bound fails the test.
function settle(call, bound) {
    return Promise.race([call.then((value) => value, (err) => err), bound.tripped]);
}

function callOauth(client, operation, args, options = {}) {
    switch (operation) {
        case 'metadata':
            return client.oauth.metadata(options);
        case 'exchangeRefreshToken':
            return client.oauth.exchangeRefreshToken(args.clientId, args.refreshToken, options);
        case 'exchangeAuthorizationCode':
            return client.oauth.exchangeAuthorizationCode(
                args.clientId, args.code, args.codeVerifier, args.redirectUri, options,
            );
        case 'revoke':
            return client.oauth.revoke(args.clientId, args.token, options);
        default:
            throw new Error(`the corpus names an operation this suite does not know: ${operation}`);
    }
}

function assertEndpoint(req, want) {
    assert.equal(`${req.method} ${req.path}`, `${want.method} ${want.path}`);
}

function assertDecoded(got, expect) {
    for (const [name, value] of Object.entries(expect.present)) {
        assert.deepEqual(got[name], value, name);
    }
    for (const name of expect.absent ?? []) {
        assert.equal(Object.hasOwn(got, name), false, `${name} must be ABSENT`);
    }
}

// A form body as a field map, decoded the way a server decodes it (+ is a space).
function formFields(body) {
    const fields = {};
    for (const [name, value] of new URLSearchParams(body)) {
        assert.equal(Object.hasOwn(fields, name), false, `${name} sent twice`);
        fields[name] = value;
    }
    return fields;
}

function assertNotError(outcome) {
    assert.ok(!(outcome instanceof Error), `rejected with ${outcome?.name}: ${outcome?.message}`);
}

// `type` is oauth (the base class exactly), accessDenied, expiredToken, or
// client: the ordinary error, which is never an OauthError. A null in the
// corpus is absence here.
function assertOutcome(err, want, label) {
    assert.ok(err instanceof VPNDetectionError, `${label}: settled with ${err}`);
    const got = `${label}: settled with ${err.name}: ${err.message}`;
    const subtype = err instanceof OauthAccessDeniedError || err instanceof OauthExpiredTokenError;
    if (want.type === 'oauth') {
        assert.ok(err instanceof OauthError && !subtype, `${got}, want the base OauthError`);
    } else if (want.type === 'accessDenied') {
        assert.ok(err instanceof OauthAccessDeniedError, `${got}, want OauthAccessDeniedError`);
    } else if (want.type === 'expiredToken') {
        assert.ok(err instanceof OauthExpiredTokenError, `${got}, want OauthExpiredTokenError`);
    } else {
        assert.equal(want.type, 'client', `${label}: unknown outcome`);
        assert.ok(!(err instanceof OauthError), `${got}, want the ordinary error`);
    }
    for (const name of ['errorCode', 'errorDescription', 'status', 'kind', 'retryable', 'message']) {
        if (name in want) {
            assert.equal(err[name], want[name] ?? undefined, `${label}: ${name}`);
        }
    }
}
