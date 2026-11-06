// The OAuth accessor against staging, on a client built with NO key, since none
// of these requests needs one. Only what is safe to repeat runs here: a real
// sign-in needs a person at the consent page, so no code is ever exchanged.

import assert from 'node:assert/strict';
import { test } from 'node:test';

// A namespace import, because a named import of a class an installed version
// lacks fails the whole file at link time instead of failing one test.
import * as vpndetection from 'vpndetection-web';

import { STAGING } from '../lib/staging.mjs';

// The only client ID the server accepts, already public in the CLI's source.
const CLIENT_ID = 'vpndetection-cli';

function keyless() {
    return new vpndetection.VPNDetection({ baseUrl: STAGING });
}

test('metadata names staging as the issuer and offers S256', async () => {
    const metadata = await keyless().oauth.metadata();

    assert.equal(metadata.issuer, STAGING);
    assert.equal(metadata.token_endpoint, `${STAGING}/oauth/token`);
    assert.ok(metadata.code_challenge_methods_supported?.includes('S256'), 'S256 is not offered');
    assert.ok(metadata.grant_types_supported?.includes('authorization_code'), 'no authorization_code grant');
});

// Answers 200 for any token, known or not, and is not rate limited.
test('revoke accepts a token that was never issued', async () => {
    await keyless().oauth.revoke(CLIENT_ID, 'mo_rt_sdk-ci-not-a-token');
});

// An unknown refresh token answers invalid_grant before anything is recorded.
test('an unknown refresh token is an invalid_grant refusal', async () => {
    await assert.rejects(keyless().oauth.exchangeRefreshToken(CLIENT_ID, 'mo_rt_sdk-ci-not-a-token'), (err) => {
        assert.ok(err instanceof vpndetection.OauthError, `${err.name}: ${err.message}`);
        assert.equal(err.errorCode, 'invalid_grant');
        assert.equal(err.status, 400);
        assert.equal(err.retryable, false);
        return true;
    });
});

// Built on the client's base URL with no request, from a pair Web Crypto made.
test('an authorization URL for staging carries a fresh S256 challenge', async () => {
    const oauth = keyless().oauth;
    const pkce = await oauth.createPkce();
    const url = new URL(oauth.authorizationUrl(CLIENT_ID, 'http://127.0.0.1:8765/callback', pkce.challenge, {
        scope: 'apikeys.use', state: 'sdk-ci',
    }));

    assert.equal(`${url.origin}${url.pathname}`, `${STAGING}/oauth/authorize`);
    assert.equal(url.searchParams.get('code_challenge'), await oauth.pkceChallenge(pkce.verifier));
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('state'), 'sdk-ci');
});
