// Loads dist in a real headless Chromium as a page with no bundler does, through an
// import map naming each dependency's browser build, with the API stubbed by
// page.route so nothing leaves the machine. `pnpm exec playwright-core install
// chromium` once, then `pnpm run test:browser`.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, join, resolve as resolvePath, sep } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright-core';

const ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), '../..');
// Resolves nowhere, so a request the stub misses fails rather than reaching a real API.
const API = 'https://api.example.test';
// The README's own examples use the default base URL, which the stub answers too:
// every request is routed, so none of them leaves the machine.
const STUBBED = new Set([API, 'https://api.vpndetection.io']);
// An origin that is not a secure context: plain http on a name that is not loopback.
const PLAIN_HOST = 'plain.test';
// The headers the API's CORS policy admits, the CORS-safelisted ones, and those only
// the browser itself may set: anything else from the client would fail a real preflight.
const ADMITTED = new Set([
    'authorization', 'content-type', 'x-api-key', 'accept', 'accept-language', 'content-language',
    'user-agent', 'referer', 'origin', 'accept-encoding', 'accept-charset', 'connection', 'content-length',
    'host', 'cookie', 'date', 'dnt', 'keep-alive', 'te', 'via',
]);
const CORS = { 'access-control-allow-origin': '*', 'access-control-expose-headers': 'Retry-After' };

let server;
let origin;
let browser;
let page;
const requests = [];
const escaped = [];
const problems = [];

before(async () => {
    const imports = browserImports(['lru-cache', 'p-limit', 'p-retry']);
    server = await serve(imports.roots, pageHtml(imports.map));
    origin = `http://127.0.0.1:${server.address().port}`;
    try {
        browser = await chromium.launch({
            channel: 'chromium', args: [`--host-resolver-rules=MAP ${PLAIN_HOST} 127.0.0.1`],
        });
    } catch (err) {
        const fix = '`pnpm exec playwright-core install chromium`';
        throw new Error(`no Chromium to run, so ${fix} first: ${err.message}`);
    }
    page = await browser.newPage();
    page.on('pageerror', (err) => problems.push(`page error: ${err.message}`));
    page.on('console', (msg) => {
        // A 4xx the stub answers on purpose is logged by the browser itself.
        if (msg.type() === 'error' && !/Failed to load resource/.test(msg.text())) {
            problems.push(`console error: ${msg.text()}`);
        }
    });
    await page.context().route('**/*', async (route) => {
        const url = new URL(route.request().url());
        if (STUBBED.has(url.origin)) {
            await answer(route);
            return;
        }
        if (url.hostname === '127.0.0.1' || url.hostname === PLAIN_HOST) {
            await route.continue();
            return;
        }
        escaped.push(url.href);
        await route.abort();
    });
    await page.goto(`${origin}/`);
});

after(async () => {
    await browser?.close();
    server?.close();
});

test('dist loads as a module in a page, with nothing of Node to lean on', async () => {
    const loaded = await page.evaluate(async () => {
        const sdk = await import('/dist/index.js');
        return {
            exports: Object.keys(sdk).sort(),
            process: typeof globalThis.process,
            secure: window.isSecureContext,
        };
    });
    assert.deepEqual(loaded.exports, [
        'DEFAULT_BASE_URL', 'OauthAccessDeniedError', 'OauthApi', 'OauthError', 'OauthExpiredTokenError',
        'VPNDetection', 'VPNDetectionError', 'isBogon',
    ]);
    assert.equal(loaded.process, 'undefined');
    assert.equal(loaded.secure, true);
});

test('a keyless lookup and myIp are served, with no Authorization header', async () => {
    const asked = requests.length;
    const got = await page.evaluate(async (api) => {
        const { VPNDetection } = await import('/dist/index.js');
        const client = new VPNDetection({ baseUrl: api });
        const result = await client.lookup('45.83.91.1');
        const me = await client.myIp();
        return { ip: result.ip, isVpn: result.isVpn, isBogon: result.isBogon, me: me.ip, meVpn: me.isVpn };
    }, API);
    assert.deepEqual(got, { ip: '45.83.91.1', isVpn: true, isBogon: false, me: '203.0.113.9', meVpn: false });
    const sent = requests.slice(asked);
    assert.deepEqual(sent.map((r) => `${r.method} ${r.path}`), ['GET /45.83.91.1', 'GET /myip']);
    for (const r of sent) {
        assert.equal(r.headers.authorization, undefined, `${r.path} carried a key`);
    }
});

test('a key goes in the Authorization header and nowhere else', async () => {
    const asked = requests.length;
    await page.evaluate(async (api) => {
        const { VPNDetection } = await import('/dist/index.js');
        await new VPNDetection({ baseUrl: api, apiKey: 'pk_smoke', cache: false }).lookup('45.83.91.1');
    }, API);
    const [sent] = requests.slice(asked);
    assert.equal(sent.headers.authorization, 'Bearer pk_smoke');
    assert.equal(sent.url.includes('pk_smoke'), false, 'the key reached the URL');
});

test('a bogon is answered without a request', async () => {
    const asked = requests.length;
    const got = await page.evaluate(async (api) => {
        const { VPNDetection, isBogon } = await import('/dist/index.js');
        const result = await new VPNDetection({ baseUrl: api }).lookup('10.0.0.1');
        return { isBogon: result.isBogon, isVpn: result.isVpn, standalone: isBogon('fe80::1') };
    }, API);
    assert.deepEqual(got, { isBogon: true, isVpn: false, standalone: true });
    assert.equal(requests.length, asked, 'a bogon reached the network');
});

test('a batch is one POST, keyed by address, its bogon answered locally', async () => {
    const asked = requests.length;
    const got = await page.evaluate(async (api) => {
        const { VPNDetection } = await import('/dist/index.js');
        const answers = await new VPNDetection({ baseUrl: api, cache: false })
            .lookupBatch(['45.83.91.1', '8.8.8.8', '10.0.0.1', '8.8.8.8']);
        return [...answers].map(([ip, a]) => [ip, a.isVpn, a.isBogon]);
    }, API);
    assert.deepEqual(got, [['45.83.91.1', true, false], ['8.8.8.8', true, false], ['10.0.0.1', false, true]]);
    const sent = requests.slice(asked);
    assert.deepEqual(sent.map((r) => `${r.method} ${r.path}`), ['POST /batch']);
    assert.deepEqual(JSON.parse(sent[0].body).ips, ['45.83.91.1', '8.8.8.8']);
    assert.match(sent[0].headers['content-type'], /^application\/json/);
});

// Retry-After is not a CORS-safelisted header: a page reads it only because the
// API exposes it, and without it every throttle would read as a spent quota.
test('a 429 reads its exposed Retry-After as a throttle', async () => {
    const got = await page.evaluate(async (api) => {
        const { VPNDetection } = await import('/dist/index.js');
        try {
            await new VPNDetection({ baseUrl: api, retries: 0 }).lookup('9.9.9.9');
            return 'answered';
        } catch (err) {
            return { kind: err.kind, retryAfterSeconds: err.retryAfterSeconds, status: err.status };
        }
    }, API);
    assert.deepEqual(got, { kind: 'rate_limited', retryAfterSeconds: 7, status: 429 });
});

test('createPkce and pkceChallenge run on Web Crypto', async () => {
    const corpus = JSON.parse(readFileSync(join(ROOT, 'testdata/testdata.json'), 'utf8')).oauth.deferred.pkce;
    const got = await page.evaluate(async ({ api, verifier }) => {
        const { VPNDetection } = await import('/dist/index.js');
        const oauth = new VPNDetection({ baseUrl: api }).oauth;
        return { pair: await oauth.createPkce(), vector: await oauth.pkceChallenge(verifier) };
    }, { api: API, verifier: corpus.verifier });
    assert.equal(got.vector, corpus.challenge);
    assert.match(got.pair.verifier, new RegExp(corpus.generatedVerifierPattern));
    assert.equal(got.pair.challenge, createHash('sha256').update(got.pair.verifier).digest('base64url'));
    assert.equal(got.pair.method, 'S256');
});

test('a code exchange posts its form with no key, and decodes the tokens', async () => {
    const asked = requests.length;
    const got = await page.evaluate(async (api) => {
        const { VPNDetection } = await import('/dist/index.js');
        const oauth = new VPNDetection({ baseUrl: api, apiKey: 'pk_smoke' }).oauth;
        const clientId = 'https://app.example/client.json';
        const url = oauth.authorizationUrl(clientId, 'https://app.example/cb', 'c'.repeat(43), {
            scope: 'apikeys.use', state: 's 1',
        });
        const token = await oauth.exchangeAuthorizationCode(
            clientId, 'mo_ac_smoke', 'v'.repeat(43), 'https://app.example/cb',
        );
        return { url: url, token: token };
    }, API);
    assert.ok(got.url.startsWith(`${API}/oauth/authorize?response_type=code&`), got.url);
    assert.ok(got.url.includes('&state=s%201'), got.url);
    assert.deepEqual(got.token, {
        access_token: 'mo_at_smoke', token_type: 'Bearer', expires_in: 3600, scope: '',
    });
    const [sent] = requests.slice(asked);
    assert.equal(`${sent.method} ${sent.path}`, 'POST /oauth/token');
    assert.match(sent.headers['content-type'], /^application\/x-www-form-urlencoded/);
    assert.equal(sent.headers.authorization, undefined, 'the key reached the token endpoint');
    assert.equal(new URLSearchParams(sent.body).get('grant_type'), 'authorization_code');
});

// The README's sessionStorage store, run as the README prints it: a reload is a
// new client, and it answers from the store with no request.
test("the README's sessionStorage store keeps an answer across a page reload", async () => {
    const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
    const block = [...readme.matchAll(/```js\n([\s\S]*?)```/g)].map((m) => m[1])
        .find((code) => code.includes('sessionStorage.getItem'));
    assert.ok(block !== undefined, 'the README has no sessionStorage store');
    const lookUp = () => page.evaluate(async (code) => {
        const { VPNDetection } = await import('/dist/index.js');
        const client = new Function('VPNDetection', `${code}\nreturn client;`)(VPNDetection);
        const result = await client.lookup('45.83.91.2');
        return { ip: result.ip, isVpn: result.isVpn, stored: Object.keys(sessionStorage).length };
    }, block);
    const asked = requests.length;
    assert.deepEqual(await lookUp(), { ip: '45.83.91.2', isVpn: true, stored: 1 });
    assert.equal(requests.length, asked + 1);
    await page.reload();
    assert.deepEqual(await lookUp(), { ip: '45.83.91.2', isVpn: true, stored: 1 });
    assert.equal(requests.length, asked + 1, 'the reloaded page asked the API again');
});

test('PKCE in a page served over plain http is refused as bad_request', async () => {
    const plain = await browser.newPage();
    try {
        await plain.goto(`http://${PLAIN_HOST}:${server.address().port}/`);
        const got = await plain.evaluate(async () => {
            const { VPNDetection } = await import('/dist/index.js');
            try {
                await new VPNDetection().oauth.createPkce();
                return { secure: window.isSecureContext, kind: 'none' };
            } catch (err) {
                return { secure: window.isSecureContext, kind: err.kind, message: err.message };
            }
        });
        assert.equal(got.secure, false);
        assert.equal(got.kind, 'bad_request', got.message);
    } finally {
        await plain.close();
    }
});

test('every request the client made stayed inside the CORS policy, and nothing else left', () => {
    // The seven the tests above make, each once: nothing retried or sent twice.
    assert.equal(requests.length, 7, requests.map((r) => `${r.method} ${r.path}`).join(', '));
    for (const r of requests) {
        const extra = Object.keys(r.headers)
            .filter((name) => !ADMITTED.has(name) && !name.startsWith('sec-') && !name.startsWith('proxy-'));
        assert.deepEqual(extra, [], `${r.method} ${r.path} sent headers the API's CORS policy does not admit`);
    }
    assert.deepEqual(escaped, []);
    assert.deepEqual(problems, []);
});

// The stand-in API: an answer per path, with the CORS headers the real one sends.
async function answer(route) {
    const request = route.request();
    const url = new URL(request.url());
    requests.push({
        method: request.method(), path: url.pathname, url: url.href, headers: request.headers(),
        body: request.postData() ?? '',
    });
    const json = (status, body, headers = {}) => route.fulfill({
        status: status,
        contentType: 'application/json',
        headers: { ...CORS, ...headers },
        body: JSON.stringify(body),
    });
    if (request.method() === 'POST' && url.pathname === '/batch') {
        const ips = JSON.parse(request.postData()).ips;
        const results = Object.fromEntries(ips.map((ip) => [ip, { ip: ip, is_vpn: true }]));
        return json(200, { results: results, errors: {} });
    }
    if (request.method() === 'POST' && url.pathname === '/oauth/token') {
        return json(200, {
            access_token: 'mo_at_smoke', token_type: 'Bearer', expires_in: 3600, scope: '', extra: 1,
        });
    }
    if (url.pathname === '/myip') {
        return json(200, { ip: '203.0.113.9', is_vpn: false });
    }
    if (url.pathname === '/9.9.9.9') {
        return json(429, { error: 'rate limit exceeded' }, { 'retry-after': '7' });
    }
    if (/^\/45\.83\.91\.\d+$/.test(url.pathname)) {
        return json(200, { ip: url.pathname.slice(1), is_vpn: true });
    }
    return json(404, { error: 'not found' });
}

// The browser build of each dependency, and of each of theirs, as an import map
// and the directory each one is served from.
function browserImports(names) {
    const map = {};
    const roots = new Map([['dist', join(ROOT, 'dist')]]);
    const visit = (name, from) => {
        if (map[name] !== undefined) {
            return;
        }
        const root = packageRoot(name, from);
        const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
        const entry = pickEntry(manifest);
        assert.ok(entry !== undefined, `${name} names no browser entry`);
        map[name] = `/deps/${name}/${entry.replace(/^\.\//, '')}`;
        roots.set(`deps/${name}`, root);
        for (const dependency of Object.keys(manifest.dependencies ?? {})) {
            visit(dependency, root);
        }
    };
    for (const name of names) {
        visit(name, ROOT);
    }
    return { map: map, roots: roots };
}

function packageRoot(name, from) {
    let dir = dirname(createRequire(join(from, 'package.json')).resolve(name));
    for (;;) {
        try {
            if (JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).name === name) {
                return dir;
            }
        } catch {
            // Not the package's own directory yet.
        }
        assert.notEqual(dirname(dir), dir, `no package root for ${name}`);
        dir = dirname(dir);
    }
}

// The entry a browser build resolves: `exports` read under the browser, import
// and default conditions, in the order the package lists them.
function pickEntry(manifest) {
    const pick = (target) => {
        if (typeof target === 'string') {
            return target;
        }
        if (target === null || typeof target !== 'object') {
            return undefined;
        }
        for (const [key, value] of Object.entries(target)) {
            if (['browser', 'import', 'default', '.'].includes(key)) {
                const found = pick(value);
                if (found !== undefined) {
                    return found;
                }
            }
        }
        return undefined;
    };
    return pick(manifest.exports) ?? manifest.module ?? manifest.main;
}

function pageHtml(importMap) {
    return '<!doctype html>\n<meta charset="utf-8">\n<title>vpndetection-web</title>\n'
        + `<script type="importmap">${JSON.stringify({ imports: importMap })}</script>\n`;
}

// Serves the page at / and each root's files beneath its prefix, nothing outside them.
function serve(roots, html) {
    const server = createServer(async (req, res) => {
        const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
        if (path === '/') {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
            res.end(html);
            return;
        }
        for (const [prefix, dir] of roots) {
            if (!path.startsWith(`/${prefix}/`)) {
                continue;
            }
            const file = resolvePath(dir, `.${path.slice(prefix.length + 1)}`);
            if (!file.startsWith(dir + sep) || !file.endsWith('.js')) {
                break;
            }
            try {
                const body = await readFile(file);
                res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
                res.end(body);
                return;
            } catch {
                break;
            }
        }
        res.writeHead(404);
        res.end();
    });
    return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}
