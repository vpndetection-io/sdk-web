// The first and last day each bot, SSH, SMTP, web, DNS resolver and BitTorrent
// detail carries are RFC 3339 dates, read as the other days of a lookup are: a
// well-formed one comes back as served, and anything else is a retried
// server_error carrying its status.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { VPNDetection } from '../dist/index.js';

const IP = '45.83.91.1';
const OTHER = '9.9.9.9';

const FIRST = '2026-08-04';
const LAST = '2026-11-15';

// Every member of every detail populated, as a paid plan's answer carries them.
const ANSWER = {
    ip: IP, is_vpn: false, is_ssh: true, is_smtp: true, is_web: true, is_dns_resolver: true, is_bittorrent: true,
    is_bot: true,
    bot: {
        provider: 'google', provider_name: 'Google', agents: ['Googlebot'], categories: ['search'], verified: true,
        identity: 'googlebot', verified_by: 'dns', confidence: 'high', first_seen: FIRST, last_seen: LAST,
    },
    ssh: {
        port: 22, banner: 'SSH-2.0-OpenSSH_9.6', host_key_fp: 'SHA256:abc', session_ok: true,
        first_seen: FIRST, last_seen: LAST,
    },
    smtp: { port: 25, banner: '220 mx.example ESMTP', session_ok: true, first_seen: FIRST, last_seen: LAST },
    web: [{
        port: 443, tls_ok: true, session_ok: true, status_code: 200, server: 'nginx', location: '', title: 'Home',
        cert_subject_cn: 'example.com', cert_subject_o: '', cert_issuer_dn: 'CN=R3', cert_browser_trusted: true,
        tls_version: 'TLS 1.3', first_seen: FIRST, last_seen: LAST,
    }],
    dns_resolver: {
        port: 53, recursion_available: true, rcode: 0, answer_correct: true, first_seen: FIRST, last_seen: LAST,
    },
    bittorrent: {
        verified: true, id_matches_ip: true, first_seen: FIRST, last_seen: LAST, last_reachable: '', days_seen: 3,
        num_ports: 1, peak_num_ports: 2, indexer: false, clients: ['qBittorrent'],
    },
};

// Where each of the twelve sits in the answer, and how to put a value there.
const MEMBERS = Object.fromEntries(['bot', 'ssh', 'smtp', 'web', 'dns_resolver', 'bittorrent'].flatMap((detail) =>
    ['first_seen', 'last_seen'].map((member) => [`${detail}.${member}`, (value) => {
        const answer = structuredClone(ANSWER);
        const at = detail === 'web' ? answer.web[0] : answer[detail];
        at[member] = value;
        return answer;
    }])));

function client(served, retries = 1) {
    const calls = [];
    const fetch = async (input, init) => {
        calls.push(input instanceof Request ? input.url : String(input));
        return new Response(JSON.stringify(served), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    return { calls: calls, client: new VPNDetection({ apiKey: 'test-key', fetch: fetch, retries: retries, cache: false }) };
}

async function refused(served, name) {
    const c = client(served);
    await assert.rejects(() => c.client.lookup(IP), (err) => {
        assert.equal(err.kind, 'server_error', `${name}: ${err.message}`);
        assert.equal(err.status, 200, name);
        return true;
    });
    assert.equal(c.calls.length, 2, `${name} is retried`);
}

test('each first and last day of a bot, SSH, SMTP, web, DNS resolver or BitTorrent detail is read', async () => {
    const result = await client(ANSWER).client.lookup(IP);
    for (const detail of [result.bot, result.ssh, result.smtp, result.web[0], result.dnsResolver, result.bittorrent]) {
        assert.equal(detail.first_seen, FIRST);
        assert.equal(detail.last_seen, LAST);
    }
    assert.equal(result.bittorrent.last_reachable, '');
    for (const day of ['2024-02-29', '0099-12-31']) {
        assert.equal((await client(MEMBERS['bot.first_seen'](day)).client.lookup(IP)).bot.first_seen, day);
    }
});

// The date probe, on the answer just read whole.
test('a bot first_seen that is not a day is a retried server_error', async () => {
    const arabicIndic = (s) => s.replace(/\d/g, (d) => String.fromCharCode(0x660 + Number(d)));
    const probe = {
        word: 'x', tomorrow: 'tomorrow', monday: 'monday', '30 February': '2026-02-30', '24:00': '2026-10-05T24:00:00Z',
        'a date with a time': '2026-10-05T10:00:00Z', '+05': '2026-10-05+05', 'a final newline': '2026-10-05\n',
        "another script's digit": arabicIndic('2026-10-05'), 'one digit': '2026-10-5', 'no dashes': '20261005',
        empty: '',
    };
    assert.equal((await client(ANSWER).client.lookup(IP)).bot.first_seen, FIRST);
    await Promise.all(Object.entries(probe).map(([name, value]) => refused(MEMBERS['bot.first_seen'](value), name)));
});

test('each of the twelve day members refuses a value that is not a day', async () => {
    assert.equal(Object.keys(MEMBERS).length, 12);
    await Promise.all(Object.entries(MEMBERS).map(([name, served]) => refused(served('x'), name)));
});

test('a batch entry whose day is not a day is that address error alone', async () => {
    const results = { [IP]: ANSWER, [OTHER]: { ...MEMBERS['smtp.last_seen']('x'), ip: OTHER } };
    const c = client({ results: results, errors: {} });
    const out = await c.client.lookupBatch([IP, OTHER]);
    assert.equal(out.get(IP).smtp.last_seen, LAST);
    assert.equal(out.get(OTHER).kind, 'server_error');
    assert.equal(out.get(OTHER).status, 200);
});
