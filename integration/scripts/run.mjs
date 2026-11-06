#!/usr/bin/env node
// Runs the integration suite against the package as PUBLISHED on the registry,
// which is the one thing the unit suite cannot check: it tests this working
// tree, so it stays green through a broken `files` list, a missing export map
// entry or a build that never ran.
//
//   node scripts/run.mjs
//
// Two conditions make the run meaningless rather than failing, and each one
// skips with a reason instead:
//
//   1. Nothing on the registry satisfies the declared range. Before the first
//      release there is no published artifact to test.
//   2. A tier's staging key is missing. The unauthenticated tests still run, and
//      each tier without a key skips from inside the suite, so the skip and its
//      reason land in the TAP output rather than in this script's preamble.
//
// npm, deliberately, not pnpm: the repo root carries a pnpm workspace whose
// `minimumReleaseAge` would refuse a version published minutes ago, and a
// workspace can resolve the dependency to the local source, which is exactly
// what this suite exists to rule out.

import { execFileSync, spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { RUNGS, skipFor } from '../lib/tiers.mjs';

const PACKAGE = 'vpndetection-web';

try {
    main();
} catch (err) {
    console.error(`==> FAILED: ${err.message}`);
    process.exitCode = 1;
}

function main() {
    const dir = dirname(dirname(fileURLToPath(import.meta.url)));
    const range = readJson(join(dir, 'package.json')).dependencies[PACKAGE];

    const versions = publishedVersions(range);
    if (versions === null) {
        skip(`${PACKAGE}@${range} is not on the registry, so there is no published artifact to test`);
        return;
    }
    console.log(`==> ${PACKAGE}@${range} matches published ${versions.join(', ')}`);
    assertRangeAdmitsLatest(range, versions);

    // Empty counts as absent: Actions interpolates a secret that does not exist
    // to an empty string, and an empty key is sent as no key at all.
    const absent = tiersWhere((rung) => skipFor(rung) !== false);
    console.log(`==> tiers with a key: ${tiersWhere((rung) => skipFor(rung) === false).join(', ')}`);
    if (absent.length > 0) {
        notice(`no staging key for ${absent.join(', ')}: those tiers are skipped`);
    }

    // Both removed so every run resolves the range afresh. A kept lockfile
    // would pin whatever the first run happened to pick, and the daily run
    // would stop noticing new releases.
    rmSync(join(dir, 'node_modules'), { recursive: true, force: true });
    rmSync(join(dir, 'package-lock.json'), { force: true });
    run('npm', ['install', '--no-audit', '--no-fund'], dir);

    assertInstalledFromRegistry(dir, versions);
    // node's own glob, not the shell's: this spawns without one.
    run('node', ['--test', 'test/*.test.mjs'], dir);
}

// `npm view <name>@<range> version` is the registry's own resolver, so the range
// is read exactly as npm will read it at install time. A package that does not
// exist and a range nothing satisfies both answer E404, and both mean the same
// thing here: there is nothing published to test yet.
function publishedVersions(range) {
    let out;
    try {
        out = execFileSync('npm', ['view', `${PACKAGE}@${range}`, 'version', '--json'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
        });
    } catch (err) {
        if (String(err.stderr ?? '').includes('E404')) {
            return null;
        }
        throw err;
    }
    const parsed = JSON.parse(out.trim());
    return Array.isArray(parsed) ? parsed : [parsed];
}

/**
 * The range has to admit the NEWEST release, not merely some release.
 *
 * A stale range still matches the last version inside it, so the skip above
 * never fires and the suite exercises a client from a major behind, reporting
 * whatever the API has changed since as a broken API. Not the same thing as the
 * range being EMPTY, which is handled above and is a skip: before a first
 * release there is genuinely nothing to test.
 */
function assertRangeAdmitsLatest(range, versions) {
    const latest = execFileSync('npm', ['view', PACKAGE, 'dist-tags.latest'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    if (versions.includes(latest)) {
        return;
    }
    throw new Error(
        `${PACKAGE}@${range} does not admit the newest published ${latest} - it would test `
        + `${versions[versions.length - 1]} instead. Bump the range in integration/package.json.`);
}

// The suite is worthless if npm handed it a link to the working tree, and that
// failure is silent: every test passes, against the wrong code.
function assertInstalledFromRegistry(dir, versions) {
    const installed = join(dir, 'node_modules', PACKAGE);
    if (lstatSync(installed).isSymbolicLink()) {
        throw new Error(`${installed} is a symlink, so the tests would run against local source`);
    }
    const entry = readJson(join(dir, 'package-lock.json')).packages[`node_modules/${PACKAGE}`];
    if (entry === undefined || !String(entry.resolved).startsWith('https://')) {
        throw new Error(`${PACKAGE} was not resolved from a registry: ${JSON.stringify(entry)}`);
    }
    const version = readJson(join(installed, 'package.json')).version;
    if (!versions.includes(version)) {
        throw new Error(`installed ${version}, which is not one of ${versions.join(', ')}`);
    }
    console.log(`==> installed ${PACKAGE}@${version} from ${entry.resolved}`);
}

function run(command, args, cwd) {
    console.log(`==> ${command} ${args.join(' ')}`);
    const res = spawnSync(command, args, { cwd: cwd, stdio: 'inherit' });
    if (res.status !== 0) {
        throw new Error(`${command} ${args.join(' ')} exited ${res.status}`);
    }
}

function tiersWhere(predicate) {
    return RUNGS.filter(predicate).map((rung) => rung.tier);
}

function readJson(path) {
    return JSON.parse(readFileSync(path, 'utf8'));
}

function skip(reason) {
    console.log(`==> SKIPPED: ${reason}`);
    notice(`Integration suite skipped: ${reason}`);
}

// Surfaced on the workflow run itself, so a skip is visible without opening the
// log and reading to the end of it.
function notice(message) {
    if (process.env.GITHUB_ACTIONS === 'true') {
        console.log(`::notice title=Integration::${message}`);
    }
}
