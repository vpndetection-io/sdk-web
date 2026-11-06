// What ships has to load in a browser as it is: no Node.js builtin, no `process`,
// and no type a consumer without Node's types cannot resolve. A bundler would hide
// any of these until a customer's build or page failed on it.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const dist = new URL('../dist/', import.meta.url).pathname;

function files(suffix) {
    const found = readdirSync(dist, { recursive: true }).filter((file) => file.endsWith(suffix));
    assert.ok(found.length > 10, `found only ${found.length} ${suffix} files in dist`);
    return found.map((file) => [file, readFileSync(join(dist, file), 'utf8')]);
}

test('no built module imports a Node.js builtin or names node:', () => {
    for (const [file, source] of files('.js')) {
        assert.doesNotMatch(source, /node:/, `${file} names a node: module`);
        const specifiers = source.match(/(?:from|import\s*\(|require\s*\()\s*['"][^'"]+['"]/g) ?? [];
        const builtin = /['"](fs|stream|crypto|path|os|http|https|url|buffer|util|events|timers)(\/[^'"]*)?['"]/;
        const builtins = specifiers.filter((spec) => builtin.test(spec));
        assert.deepEqual(builtins, [], `${file} imports a Node.js builtin`);
    }
});

test('no built module reads process or require', () => {
    for (const [file, source] of files('.js')) {
        assert.doesNotMatch(source, /\bprocess\b/, `${file} reads process`);
        assert.doesNotMatch(source, /\brequire\s*\(/, `${file} calls require`);
    }
});

test('every relative import names its .js file, as a browser needs', () => {
    for (const [file, source] of files('.js')) {
        for (const [, spec] of source.matchAll(/(?:from|import\s*\()\s*['"](\.[^'"]*)['"]/g)) {
            assert.match(spec, /\.js$/, `${file} imports ${spec}`);
        }
    }
});

test("no declaration needs Node's types", () => {
    for (const [file, source] of files('.d.ts')) {
        assert.doesNotMatch(source, /node:|\bNodeJS\.|\bBuffer\b|\bprocess\b/, `${file} names a Node type`);
    }
});

test('the only bare imports are the three runtime dependencies', () => {
    const allowed = new Set(['lru-cache', 'p-limit', 'p-retry']);
    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    assert.deepEqual(Object.keys(manifest.dependencies).sort(), [...allowed].sort());
    for (const [file, source] of files('.js')) {
        for (const [, spec] of source.matchAll(/(?:from|import\s*\()\s*['"]([^'"./][^'"]*)['"]/g)) {
            assert.ok(allowed.has(spec), `${file} imports ${spec}`);
        }
    }
});
