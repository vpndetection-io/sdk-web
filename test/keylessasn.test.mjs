// An Unlimited answer, with a key or without one, carries no `type` on its AS: the spec stopped
// requiring it in 2026.11.26. The client reads such an answer, in a lookup, a batch entry, the
// cache and a store, and `Asn.type` keeps the `string` it had: a `Result` reads an absent one as an
// empty string, while `raw` shows what was served. A present one reads as served, and one of the
// wrong JSON type, or null, is still no answer.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import ts from 'typescript';

import { VPNDetection } from '../dist/index.js';

const IP = '66.249.66.1';
const OTHER = '9.9.9.9';

const ASN = {
    asn: 15169, name: 'Google LLC', domain: 'google.com', prefix: '66.249.64.0/20', country: 'US',
    rpki_status: 'valid',
};
const served = (ip, asn) => ({ ip: ip, is_vpn: false, is_tor: false, is_relay: false, asn: asn });

// A fetch answering every lookup, myip and batch entry with `reply(ip)`, and counting its requests.
function api(reply) {
    const state = { calls: 0 };
    const fetch = async (input) => {
        state.calls += 1;
        const path = new URL(input.url).pathname;
        if (path === '/batch') {
            const ips = JSON.parse(await input.text()).ips;
            return Response.json({ results: Object.fromEntries(ips.map((ip) => [ip, reply(ip)])), errors: {} });
        }
        return Response.json(reply(path === '/myip' ? IP : decodeURIComponent(path.slice(1))));
    };
    return { fetch: fetch, state: state };
}

const client = (server, options = {}) => new VPNDetection({ fetch: server.fetch, retries: 2, ...options });

function assertKeyless(result, label) {
    assert.deepEqual(result.asn, { ...ASN, type: '' }, `${label}: asn reads with an empty type`);
    assert.equal(typeof result.asn.type, 'string', `${label}: type stays a string`);
    assert.deepEqual(result.raw.asn, ASN, `${label}: raw.asn is what was served`);
    assert.ok(!('type' in result.raw.asn), `${label}: raw.asn has no type`);
}

test('an answer without the AS type is read by a lookup, myIp and a batch', async () => {
    const server = api((ip) => served(ip, ASN));
    const c = client(server, { cache: false });

    assertKeyless(await c.lookup(IP), 'lookup');
    assertKeyless(await c.myIp(), 'myIp');
    const batch = await c.lookupBatch([IP, OTHER]);
    assertKeyless(batch.get(IP), 'batch');
    assertKeyless(batch.get(OTHER), 'batch other');
});

test('the in-memory cache and a store give the same reading as the network', async () => {
    const entries = new Map();
    const store = {
        get: (key) => entries.get(key),
        set: (key, result) => void entries.set(key, structuredClone(result)),
    };
    const server = api((ip) => served(ip, ASN));
    const first = client(server, { cache: { store: store } });
    assertKeyless(await first.lookup(IP), 'network');
    assertKeyless(await first.lookup(IP), 'memory');
    assert.equal(server.state.calls, 1, 'the second lookup was a cache hit');

    const second = client(server, { cache: { store: store } });
    assertKeyless(await second.lookup(IP), 'store');
    assert.equal(server.state.calls, 1, 'the store answered without a request');
});

test('a present AS type reads as served, an empty one included', async () => {
    for (const type of ['hosting', '']) {
        const asn = { ...ASN, type: type };
        const c = client(api((ip) => served(ip, asn)), { cache: false });
        for (const result of [await c.lookup(IP), await c.myIp(), (await c.lookupBatch([IP])).get(IP)]) {
            assert.deepEqual(result.asn, asn, `type ${JSON.stringify(type)}`);
            assert.deepEqual(result.raw.asn, asn, `raw, type ${JSON.stringify(type)}`);
        }
    }
});

test('an AS type of the wrong JSON type, or null, is a retried server_error', async () => {
    for (const type of [null, 7, true, {}, []]) {
        const asn = { ...ASN, type: type };
        const label = JSON.stringify(type);
        for (const [name, call] of [['lookup', (c) => c.lookup(IP)], ['myIp', (c) => c.myIp()]]) {
            const server = api((ip) => served(ip, asn));
            await assert.rejects(() => call(client(server, { cache: false })), (err) => {
                assert.equal(err.kind, 'server_error', `${name} ${label}: ${err.message}`);
                assert.equal(err.status, 200, `${name} ${label}`);
                return true;
            });
            assert.equal(server.state.calls, 3, `${name} ${label} is retried`);
        }
        // One entry it cannot read is that address's error alone, beside one it can.
        const server = api((ip) => served(ip, ip === IP ? ASN : asn));
        const out = await client(server, { cache: false }).lookupBatch([IP, OTHER]);
        assertKeyless(out.get(IP), `batch ${label}`);
        assert.equal(out.get(OTHER).kind, 'server_error', `batch entry ${label}`);
    }
});

// The AS's other members are still required, as the spec says.
test('an AS without any other member is still a retried server_error', async () => {
    for (const member of Object.keys(ASN)) {
        const { [member]: _gone, ...asn } = ASN;
        const server = api((ip) => served(ip, asn));
        await assert.rejects(() => client(server, { cache: false }).lookup(IP), (err) => err.kind === 'server_error');
        assert.equal(server.state.calls, 3, `${member} is retried`);
    }
});

// The type is held to the spec, so an AS member it makes optional, or one it stops requiring, is seen.
const GENERATED = readFileSync(new URL('../src/generated/types.gen.ts', import.meta.url), 'utf8');

test('the AS type is an optional member of the generated type, and listed as never null', async () => {
    const shapes = await import('../dist/shapes.js');
    const block = GENERATED.split('export type Asn = {\n')[1]?.split('\n};')[0];
    assert.ok(block !== undefined, 'types.gen.ts has no Asn');
    const optional = [...block.matchAll(/^ {4}([a-z][a-z0-9_]*)\?: (.*)$/gm)]
        .filter((m) => !/\| null;$/.test(m[2])).map((m) => m[1]);
    assert.deepEqual([...shapes.ASN_NOT_NULL].sort(), optional.sort());
});

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PROGRAM = `${ROOT}held-asn-type-check.ts`;

// Typed as the previous release typed them: each assignment is a compile error once `type` moves.
const SOURCE = `
import type { Asn, LookupResponse, Result } from './dist/index.js';

export function held(r: Result, raw: LookupResponse, asn: Asn): void {
    const types: string[] = [asn.type, r.asn!.type, r.raw.asn!.type, raw.asn!.type];
    const whole: Asn = { asn: 1, name: '', domain: '', type: '', prefix: '', country: '', rpki_status: '' };
    void [types, whole];
}
`;

test('a program typed against the previous release still compiles: Asn.type stays a string', () => {
    const options = {
        target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
        strict: true, noEmit: true, skipLibCheck: true, types: [], lib: ['lib.es2022.d.ts', 'lib.dom.d.ts'],
    };
    const host = ts.createCompilerHost(options);
    const read = host.getSourceFile.bind(host);
    host.getSourceFile = (name, ...rest) => (
        name === PROGRAM ? ts.createSourceFile(name, SOURCE, ts.ScriptTarget.ES2022) : read(name, ...rest)
    );
    const exists = host.fileExists.bind(host);
    host.fileExists = (name) => name === PROGRAM || exists(name);

    const program = ts.createProgram([PROGRAM], options, host);
    const errors = ts.getPreEmitDiagnostics(program).map((d) => ts.flattenDiagnosticMessageText(d.messageText, '\n'));
    assert.deepEqual(errors, []);
});
