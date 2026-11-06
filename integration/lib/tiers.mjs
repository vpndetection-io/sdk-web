// Which plan tiers this run can observe, and the secret each one needs.
//
// Imported by `scripts/run.mjs` as well as by the tests, so it must not import
// the package under test: the runner reads it BEFORE `npm install` has put
// anything in `node_modules`.
//
// A tier is observable only when its secret holds something non-empty. Actions
// interpolates a secret that does not exist to an EMPTY STRING rather than
// leaving the variable unset, and `new VPNDetection({ apiKey: '' })` sends no
// auth header at all, so an empty key runs as a second unauthenticated client
// and every comparison against it is vacuously true.

// Ascending, one rung per plan tier. `widens` is what the rung promises against
// whichever observable rung sits below it: a free key serves strictly more than
// no key, and the first paid tier strictly more than a free key; every paid
// plan answers the same fields, so a higher paid tier only keeps what the one
// under it serves.
//
// Field COUNTS are deliberately absent. Pinning "starter answers seven fields"
// turns a pricing change into a red SDK build; the relation between the tiers is
// what the client actually has to keep.
export const RUNGS = [
    { tier: 'unauth', secret: null, widens: false },
    { tier: 'free', secret: 'VPNDETECTION_STAGING_KEY_FREE', widens: true },
    { tier: 'starter', secret: 'VPNDETECTION_STAGING_KEY_STARTER', widens: true },
    { tier: 'scale', secret: 'VPNDETECTION_STAGING_KEY_SCALE', widens: false },
    { tier: 'max', secret: 'VPNDETECTION_STAGING_KEY_MAX', widens: false },
];

export const UNAUTH_RUNG = RUNGS[0];
export const MAX_RUNG = RUNGS[RUNGS.length - 1];

export function keyFor(rung) {
    if (rung.secret === null) {
        return '';
    }
    return (process.env[rung.secret] ?? '').trim();
}

// A reason string, or false, which is the shape node:test's `skip` option wants.
export function skipFor(rung) {
    if (rung.secret === null || keyFor(rung) !== '') {
        return false;
    }
    return `${rung.secret} is not set, so the ${rung.tier} tier cannot be exercised`;
}

export function observableRungs() {
    return RUNGS.filter((rung) => skipFor(rung) === false);
}
