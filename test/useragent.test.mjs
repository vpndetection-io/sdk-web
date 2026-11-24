// A visitor's user agent, sent with a lookup, `myIp` or a batch: how it reaches
// the API, what the cache, the store and the requests in flight key on, and how
// the answer's verdict comes back.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { VPNDetection } from '../dist/index.js';

const IP = '66.249.66.1';
const OTHER = '9.9.9.9';
const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const CHROME = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36';

const verdictFor = (agent) => (agent.includes('Googlebot')
    ? { agent: 'Googlebot', kind: 'bot', verdict: 'verified' }
    : { agent: 'Chrome', kind: 'browser', verdict: 'not_bot' });

// An origin that answers a lookup with the verdict for the agent it was sent, and
// each batch address with the verdict for its entry in `user_agents`, recording
// every request. `delayMs` holds each answer so concurrent calls overlap.
function origin(delayMs = 0) {
    const requests = [];
    const fetch = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        const url = new URL(request.url);
        const body = request.method === 'POST' ? JSON.parse(await request.text()) : null;
        requests.push({ url: request.url, search: url.search, body: body });
        if (delayMs > 0) {
            await new Promise((r) => setTimeout(r, delayMs));
        }
        const answer = (ip, agent) => ({
            ip: ip, is_vpn: false, ...(agent === undefined || agent === null ? {} : { user_agent: verdictFor(agent) }),
        });
        let served;
        if (body !== null) {
            const results = {};
            for (const ip of body.ips) {
                results[ip] = answer(ip, body.user_agents?.[ip]);
            }
            served = { results: results, errors: {} };
        } else {
            const ip = url.pathname === '/myip' ? '203.0.113.9' : decodeURIComponent(url.pathname.slice(1));
            served = answer(ip, url.searchParams.get('user_agent'));
        }
        return new Response(JSON.stringify(served), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    return { requests: requests, fetch: fetch };
}

function clientOn(o, options = {}) {
    return new VPNDetection({ apiKey: 'test-key', fetch: o.fetch, retries: 0, ...options });
}

test('a lookup sends its user agent percent-encoded, and the answer carries the verdict', async () => {
    const o = origin();
    const result = await clientOn(o).lookup(IP, { userAgent: GOOGLEBOT });
    assert.equal(o.requests.length, 1);
    const search = o.requests[0].search;
    assert.equal(new URL(o.requests[0].url).searchParams.get('user_agent'), GOOGLEBOT);
    // Every reserved character encoded: `+` above all, which a server reads as a space.
    assert.equal(search, `?user_agent=${'Mozilla%2F5.0%20%28compatible%3B%20Googlebot%2F2.1%3B%20%2Bhttp%3A%2F%2Fwww.google.com%2Fbot.html%29'}`);
    assert.doesNotMatch(search.slice(1), /[+()/;:]/);
    assert.deepEqual(result.userAgent, { agent: 'Googlebot', kind: 'bot', verdict: 'verified' });
    assert.deepEqual(result.raw.user_agent, result.userAgent);
});

test('no user agent, or an empty one, sends none and the answer carries none', async () => {
    const o = origin();
    const client = clientOn(o, { cache: false });
    for (const options of [{}, { userAgent: '' }, { userAgent: undefined }]) {
        const result = await client.lookup(IP, options);
        assert.equal(result.userAgent, undefined);
        assert.ok(!('userAgent' in result));
    }
    const sent = await client.lookup(IP, { userAgent: CHROME });
    assert.equal(sent.userAgent.verdict, 'not_bot');
    assert.deepEqual(o.requests.map((r) => r.search), ['', '', '', `?user_agent=${encodeURIComponent(CHROME).replace(/[()]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)}`]);
});

test('a user agent longer than the API takes is sent whole, never refused', async () => {
    const o = origin();
    const long = `Mozilla/5.0 ${'x'.repeat(2000)}`;
    const result = await clientOn(o).lookup(IP, { userAgent: long });
    assert.equal(o.requests.length, 1);
    assert.equal(new URL(o.requests[0].url).searchParams.get('user_agent'), long);
    assert.equal(result.userAgent.agent, 'Chrome');
});

test('the cache keys on the address and the user agent together', async () => {
    const o = origin();
    const client = clientOn(o);
    const google = await client.lookup(IP, { userAgent: GOOGLEBOT });
    const chrome = await client.lookup(IP, { userAgent: CHROME });
    assert.equal(o.requests.length, 2, 'two agents for one address are two requests');
    assert.equal(google.userAgent.verdict, 'verified');
    assert.equal(chrome.userAgent.verdict, 'not_bot');
    assert.equal((await client.lookup(IP, { userAgent: GOOGLEBOT })).userAgent.verdict, 'verified');
    assert.equal(o.requests.length, 2, 'the same pair again is a cache hit');
    const plain = await client.lookup(IP);
    assert.equal(o.requests.length, 3, "the address's plain answer is its own");
    assert.equal(plain.userAgent, undefined);
    assert.equal((await client.lookup(IP, { userAgent: '' })).userAgent, undefined);
    assert.equal(o.requests.length, 3, 'an empty agent is the plain answer');
});

test('concurrent misses for one address and user agent share one request', async () => {
    const o = origin(30);
    const client = clientOn(o);
    const answers = await Promise.all([
        client.lookup(IP, { userAgent: GOOGLEBOT }), client.lookup(IP, { userAgent: GOOGLEBOT }),
        client.lookup(IP, { userAgent: CHROME }), client.lookup(IP),
        client.lookupBatch([IP, OTHER], { userAgents: { [IP]: GOOGLEBOT } }),
    ]);
    assert.equal(o.requests.length, 4, 'one request per pair, the batch awaiting the Googlebot lookup');
    assert.equal(answers[0], answers[1]);
    assert.equal(answers[4].get(IP), answers[0]);
    assert.equal(answers[2].userAgent.verdict, 'not_bot');
    assert.equal(answers[3].userAgent, undefined);
    const batch = o.requests.find((r) => r.body !== null);
    assert.deepEqual(batch.body, { ips: [OTHER] }, 'the batch sends only what it leads');
});

test('a batch sends user_agents keyed by each address as it is sent', async () => {
    const o = origin();
    const client = clientOn(o, { cache: false });
    const out = await client.lookupBatch([IP, '::ffff:1.1.1.1', OTHER], {
        userAgents: { [IP]: GOOGLEBOT, '::ffff:1.1.1.1': CHROME, '8.8.8.8': CHROME },
    });
    assert.equal(o.requests.length, 1);
    assert.deepEqual(o.requests[0].body, {
        ips: [IP, '1.1.1.1', OTHER], user_agents: { [IP]: GOOGLEBOT, '1.1.1.1': CHROME },
    });
    assert.equal(out.get(IP).userAgent.verdict, 'verified');
    assert.equal(out.get('::ffff:1.1.1.1').userAgent.verdict, 'not_bot');
    assert.equal(out.get(OTHER).userAgent, undefined);

    const fromMap = await client.lookupBatch([IP, OTHER], { userAgents: new Map([[OTHER, CHROME]]) });
    assert.deepEqual(o.requests[1].body, { ips: [IP, OTHER], user_agents: { [OTHER]: CHROME } });
    assert.equal(fromMap.get(OTHER).userAgent.verdict, 'not_bot');
});

test('a batch chunk where no address has a user agent sends no user_agents', async () => {
    const o = origin();
    const client = clientOn(o, { cache: false });
    for (const userAgents of [undefined, {}, { [IP]: '' }, new Map()]) {
        await client.lookupBatch([IP, OTHER], { userAgents: userAgents });
    }
    assert.ok(o.requests.every((r) => !('user_agents' in r.body)), JSON.stringify(o.requests.map((r) => r.body)));
    // 1001 addresses are two chunks, and only the second carries an agent.
    const addrs = Array.from({ length: 1001 }, (_, i) => `9.0.${Math.floor(i / 256)}.${i % 256}`);
    o.requests.length = 0;
    const out = await client.lookupBatch(addrs, { userAgents: { [addrs[1000]]: GOOGLEBOT } });
    assert.equal(o.requests.length, 2);
    const [first, second] = [...o.requests].sort((a, b) => b.body.ips.length - a.body.ips.length);
    assert.ok(!('user_agents' in first.body));
    assert.deepEqual(second.body, { ips: [addrs[1000]], user_agents: { [addrs[1000]]: GOOGLEBOT } });
    assert.equal(out.get(addrs[1000]).userAgent.verdict, 'verified');
});

test('a bogon is answered locally with no verdict, its user agent sent nowhere', async () => {
    const o = origin();
    const client = clientOn(o);
    const bogon = await client.lookup('10.0.0.1', { userAgent: GOOGLEBOT });
    assert.equal(bogon.isBogon, true);
    assert.ok(!('userAgent' in bogon));
    assert.equal(o.requests.length, 0);
    const out = await client.lookupBatch(['10.0.0.1', IP], { userAgents: { '10.0.0.1': GOOGLEBOT, [IP]: GOOGLEBOT } });
    assert.ok(!('userAgent' in out.get('10.0.0.1')));
    assert.equal(o.requests.length, 1);
    assert.deepEqual(o.requests[0].body, { ips: [IP], user_agents: { [IP]: GOOGLEBOT } });
    assert.equal(out.get(IP).userAgent.verdict, 'verified');
});

test('a batch reads the cache on the address and its user agent', async () => {
    const o = origin();
    const client = clientOn(o);
    await client.lookup(IP, { userAgent: GOOGLEBOT });
    const hit = await client.lookupBatch([IP], { userAgents: { [IP]: GOOGLEBOT } });
    assert.equal(o.requests.length, 1, 'the pair is cached');
    assert.equal(hit.get(IP).userAgent.verdict, 'verified');
    const other = await client.lookupBatch([IP, OTHER], { userAgents: { [IP]: CHROME } });
    assert.equal(o.requests.length, 2);
    assert.deepEqual(o.requests[1].body, { ips: [IP, OTHER], user_agents: { [IP]: CHROME } });
    assert.equal(other.get(IP).userAgent.verdict, 'not_bot');
    assert.equal((await client.lookup(IP, { userAgent: CHROME })).userAgent.verdict, 'not_bot');
    assert.equal(o.requests.length, 2, "the batch's answer is cached on its pair");
});

test('the store keys an answer to a user agent apart from the plain one', async () => {
    const o = origin();
    const entries = new Map();
    const store = { get: (key) => entries.get(key), set: (key, result) => void entries.set(key, result) };
    await clientOn(o, { cache: { store: store } }).lookup(IP, { userAgent: GOOGLEBOT });
    const keys = [...entries.keys()];
    assert.equal(keys.length, 1);
    assert.match(keys[0], /^[0-9a-f]{16}:66\.249\.66\.1\?user_agent=Mozilla%2F5\.0%20%28compatible/);
    // A fresh client on the same store: the pair is read back, the plain lookup is not.
    const again = clientOn(o, { cache: { store: store } });
    assert.equal((await again.lookup(IP, { userAgent: GOOGLEBOT })).userAgent.verdict, 'verified');
    assert.equal(o.requests.length, 1);
    assert.equal((await again.lookup(IP)).userAgent, undefined);
    assert.equal(o.requests.length, 2);
    const batch = await clientOn(o, { cache: { store: store } }).lookupBatch([IP], { userAgents: { [IP]: GOOGLEBOT } });
    assert.equal(o.requests.length, 2, 'a batch reads the pair from the store');
    assert.equal(batch.get(IP).userAgent.verdict, 'verified');
});

test('myIp sends its user agent and stays uncached', async () => {
    const o = origin();
    const client = clientOn(o);
    const first = await client.myIp({ userAgent: GOOGLEBOT });
    await client.myIp({ userAgent: GOOGLEBOT });
    assert.equal(o.requests.length, 2);
    assert.equal(new URL(o.requests[0].url).pathname, '/myip');
    assert.equal(new URL(o.requests[0].url).searchParams.get('user_agent'), GOOGLEBOT);
    assert.match(o.requests[0].search, /%2Bhttp/);
    assert.equal(first.userAgent.verdict, 'verified');
});

test('a user agent that is no string, or agents that are no map, are refused before anything is sent', async () => {
    const o = origin();
    const client = clientOn(o);
    for (const call of [
        () => client.lookup(IP, { userAgent: 5 }), () => client.myIp({ userAgent: {} }),
        () => client.lookupBatch([IP], { userAgents: 'Googlebot' }),
        () => client.lookupBatch([IP], { userAgents: { [IP]: 5 } }),
    ]) {
        await assert.rejects(call, (err) => err.kind === 'bad_request');
    }
    assert.equal(o.requests.length, 0);
});

test('a verdict without its members is unreadable, and a new verdict comes back as served', async () => {
    const serve = (verdict) => async () => new Response(JSON.stringify({ ip: IP, is_vpn: false, user_agent: verdict }), {
        status: 200, headers: { 'content-type': 'application/json' },
    });
    for (const verdict of [{ agent: 'Googlebot', kind: 'bot' }, { agent: 'Googlebot', kind: 'bot', verdict: 1 }, 'verified']) {
        const client = new VPNDetection({ apiKey: 'k', fetch: serve(verdict), retries: 0, cache: false });
        await assert.rejects(() => client.lookup(IP, { userAgent: GOOGLEBOT }), (err) => {
            assert.equal(err.kind, 'server_error', JSON.stringify(verdict));
            assert.equal(err.status, 200);
            return true;
        });
    }
    const added = { agent: 'Googlebot', kind: 'bot', verdict: 'stale' };
    const client = new VPNDetection({ apiKey: 'k', fetch: serve(added), retries: 0, cache: false });
    assert.deepEqual((await client.lookup(IP, { userAgent: GOOGLEBOT })).userAgent, added);
});
