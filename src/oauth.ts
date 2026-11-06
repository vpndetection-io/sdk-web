import type { Client } from './generated/client/index.js';
import { oauthMetadata, oauthRevoke, oauthToken } from './generated/sdk.gen.js';
import type { TokenRequest } from './generated/types.gen.js';

import { errorFromResponse, oauthErrorFrom, VPNDetectionError } from './errors.js';
import { checkTimeout, deadline, noResponse, withRetry, type Res } from './transport.js';

/** Per-call overrides for one OAuth request. Anything omitted falls back to the client's setting. */
export interface OauthOptions {
    /** How long one attempt may take before it is abandoned, in milliseconds. */
    timeoutMs?: number;
}

/** What an authorization URL asks for beyond what every one carries. A member left out is left out. */
export interface AuthorizationUrlOptions {
    /** Space-delimited scopes, sent as given. The server narrows them to what the client may ask for. */
    scope?: string;
    /** Comes back on the redirect unchanged, so the caller can tell the answer is to its own request. */
    state?: string;
    /** The API the tokens are meant for. */
    resource?: string;
}

/** One sign-in's PKCE pair: `challenge` goes in the authorization URL, `verifier` to the exchange. */
export interface Pkce {
    /** 32 random bytes as 43 characters of unpadded base64url, sent only to the exchange. */
    verifier: string;
    /** The verifier's SHA-256, as unpadded base64url. */
    challenge: string;
    /** `S256`, the only method the server accepts. */
    method: 'S256';
}

/** The authorization server's discovery document. No call here needs it: each builds on the base URL. */
export interface OauthMetadata {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    device_authorization_endpoint?: string;
    revocation_endpoint?: string;
    scopes_supported?: string[];
    response_types_supported?: string[];
    grant_types_supported?: string[];
    code_challenge_methods_supported?: string[];
    token_endpoint_auth_methods_supported?: string[];
    authorization_response_iss_parameter_supported?: boolean;
    client_id_metadata_document_supported?: boolean;
    registration_endpoint?: string;
    service_documentation?: string;
}

/**
 * What a completed sign-in or a refresh hands back.
 *
 * `apikey_id` is set when the person picked one of their API keys and may still
 * read it back. `apikey`, the key itself, also needs a sign-in rather than a
 * refresh and a key whose secret can be shown again, so `apikey_id` without
 * `apikey` is normal. An app signing in with a client metadata document is never
 * handed a key. An empty `scope` is present.
 */
export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    /** Spent by the refresh that presents it, so keep the one each refresh returns. */
    refresh_token?: string;
    scope?: string;
    apikey_id?: string;
    apikey?: string;
}

/**
 * Signs a person in through their browser with the OAuth authorization code flow
 * and PKCE, so an app or an extension can act for them. Reached through
 * `client.oauth`.
 *
 * Every call takes a client ID: one issued on request from
 * support@vpndetection.io, or the https URL of a client metadata document the app
 * serves. None of these requests carries the client's API key, and none needs one.
 */
export class OauthApi {
    constructor(
        private readonly client: Client,
        private readonly retries: number,
        private readonly timeoutMs: number,
    ) {}

    async metadata(options: OauthOptions = {}): Promise<OauthMetadata> {
        checkTimeout(options.timeoutMs);
        return withRetry(this.retries, async () => {
            const res = await deadline(options.timeoutMs ?? this.timeoutMs, (signal) => oauthMetadata({
                client: this.client, signal: signal,
            }));
            return decode(res, METADATA);
        });
    }

    /**
     * The URL to send the person's browser to. Makes no request. Once they
     * decide, the server redirects to `redirectUri` with a `code` for
     * `exchangeAuthorizationCode` (and `state`, when one was given), or with an
     * `error`.
     */
    authorizationUrl(
        clientId: string, redirectUri: string, codeChallenge: string,
        options: AuthorizationUrlOptions = {},
    ): string {
        const params: [string, string | undefined][] = [
            ['response_type', 'code'],
            ['client_id', clientId],
            ['redirect_uri', redirectUri],
            ['code_challenge', codeChallenge],
            ['code_challenge_method', 'S256'],
            ['scope', options.scope || undefined],
            ['state', options.state || undefined],
            ['resource', options.resource || undefined],
        ];
        const query = params
            .filter((param): param is [string, string] => param[1] !== undefined)
            .map(([name, value]) => `${name}=${percentEncode(name, value)}`)
            .join('&');
        return `${this.client.getConfig().baseUrl ?? ''}/oauth/authorize?${query}`;
    }

    /**
     * Trade the `code` a sign-in's redirect brought back for tokens.
     * `codeVerifier` is the PKCE verifier whose challenge went into the
     * authorization URL, and `redirectUri` that URL's, exactly.
     *
     * Never retried: the server spends the code on first read, before it checks
     * the verifier, so a retry could only be refused.
     */
    async exchangeAuthorizationCode(
        clientId: string, code: string, codeVerifier: string, redirectUri: string,
        options: OauthOptions = {},
    ): Promise<TokenResponse> {
        return this.exchange({
            grant_type: 'authorization_code', code: code, redirect_uri: redirectUri,
            client_id: clientId, code_verifier: codeVerifier,
        }, options.timeoutMs);
    }

    /**
     * Trade a refresh token for a new pair. The old one is spent whatever happens
     * next, so this is never retried. A refresh names the key the person picked
     * (`apikey_id`) but never reveals it again (`apikey`).
     */
    async exchangeRefreshToken(
        clientId: string, refreshToken: string, options: OauthOptions = {},
    ): Promise<TokenResponse> {
        return this.exchange({
            grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId,
        }, options.timeoutMs);
    }

    /**
     * A fresh PKCE pair for one sign-in, from the browser's secure random source.
     *
     * Async, as Web Crypto's digest is. A page served over plain http has no Web
     * Crypto digest at all, so there it rejects as `bad_request`.
     */
    async createPkce(): Promise<Pkce> {
        const verifier = base64url(webCrypto().getRandomValues(new Uint8Array(32)));
        return { verifier: verifier, challenge: await challengeFor(verifier), method: 'S256' };
    }

    /** The `S256` challenge for a PKCE verifier: its SHA-256, as unpadded base64url. */
    async pkceChallenge(verifier: string): Promise<string> {
        return challengeFor(verifier);
    }

    /**
     * End a token. A refresh token ends the whole sign-in and every token it
     * issued, which is how an app signs the person out; an access token ends
     * only itself. The server answers the same for any token, known or not.
     */
    async revoke(clientId: string, token: string, options: OauthOptions = {}): Promise<void> {
        checkTimeout(options.timeoutMs);
        await withRetry(this.retries, async () => {
            const res = await deadline(options.timeoutMs ?? this.timeoutMs, (signal) => oauthRevoke({
                client: this.client,
                body: { token: token, client_id: clientId },
                // The answer says nothing, so it is read as text and dropped rather than parsed.
                parseAs: 'text',
                signal: signal,
            }));
            throwIfFailed(res);
        });
    }

    private async exchange(form: TokenRequest, timeoutMs?: number): Promise<TokenResponse> {
        checkTimeout(timeoutMs);
        const res = await deadline(timeoutMs ?? this.timeoutMs, (signal) => oauthToken({
            client: this.client, body: form, signal: signal,
        }));
        return decode(res, TOKEN_RESPONSE);
    }
}

async function challengeFor(verifier: string): Promise<string> {
    if (typeof verifier !== 'string') {
        throw new VPNDetectionError('bad_request', `verifier must be a string, got ${typeof verifier}`);
    }
    const digest = await webCrypto().subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64url(new Uint8Array(digest));
}

// A browser offers Web Crypto's digest only to a secure context: https, or a
// page on the loopback address. Refused by name here rather than failing as a
// TypeError on `undefined`.
function webCrypto(): Crypto {
    const crypto = (globalThis as { crypto?: Crypto }).crypto;
    if (crypto?.subtle === undefined || typeof crypto.getRandomValues !== 'function') {
        throw new VPNDetectionError(
            'bad_request', 'PKCE needs Web Crypto, which this context lacks: serve the page over https',
        );
    }
    return crypto;
}

function base64url(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Every byte of the value's UTF-8 as %XX but A-Z a-z 0-9 - . _ ~, so a space is
// %20 and never +. encodeURIComponent alone leaves ! ' ( ) * as they are, and
// throws a URIError on a lone surrogate, which has no UTF-8 at all.
function percentEncode(name: string, value: string): string {
    if (typeof value !== 'string' || value === '') {
        throw new VPNDetectionError('bad_request', `${name} must be a non-empty string`);
    }
    try {
        return encodeURIComponent(value)
            .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
    } catch {
        throw new VPNDetectionError('bad_request', `${name} is not valid UTF-16, so it has no UTF-8 to send`);
    }
}

interface Member {
    type: 'string' | 'integer' | 'boolean' | 'string[]';
    required?: true;
    /** The name on the wire, where it differs from the one surfaced. */
    wire?: string;
}

const METADATA: Record<keyof OauthMetadata, Member> = {
    issuer: { type: 'string', required: true },
    authorization_endpoint: { type: 'string', required: true },
    token_endpoint: { type: 'string', required: true },
    device_authorization_endpoint: { type: 'string' },
    revocation_endpoint: { type: 'string' },
    scopes_supported: { type: 'string[]' },
    response_types_supported: { type: 'string[]' },
    grant_types_supported: { type: 'string[]' },
    code_challenge_methods_supported: { type: 'string[]' },
    token_endpoint_auth_methods_supported: { type: 'string[]' },
    authorization_response_iss_parameter_supported: { type: 'boolean' },
    client_id_metadata_document_supported: { type: 'boolean' },
    registration_endpoint: { type: 'string' },
    service_documentation: { type: 'string' },
};

const TOKEN_RESPONSE: Record<keyof TokenResponse, Member> = {
    access_token: { type: 'string', required: true },
    token_type: { type: 'string', required: true },
    expires_in: { type: 'integer', required: true },
    refresh_token: { type: 'string' },
    scope: { type: 'string' },
    apikey_id: { type: 'string', wire: 'mslm:apikey_id' },
    apikey: { type: 'string', wire: 'mslm:apikey' },
};

// Only the declared members are copied, on PRESENCE, so an absent one stays
// absent and an empty `scope` stays present. Anything else the server sends is
// dropped rather than surfaced untyped.
function decode<T>(res: Res, members: Record<keyof T, Member>): T {
    const status = throwIfFailed(res).status;
    if (res.error !== undefined) {
        // A 2xx the generated client could not parse, which reports it here: as
        // unreadable as an object missing a member, so the same retried error.
        throw new VPNDetectionError('server_error', 'the answer was not JSON', status);
    }
    const body = res.data;
    if (!isObject(body)) {
        throw new VPNDetectionError('server_error', 'the answer was not a JSON object', status);
    }
    const out: Record<string, unknown> = {};
    for (const [name, member] of Object.entries<Member>(members)) {
        const wire = member.wire ?? name;
        const value = body[wire];
        if (value === undefined || value === null) {
            if (member.required) {
                throw new VPNDetectionError('server_error', `the answer carried no ${wire}`, status);
            }
            continue;
        }
        if (!hasType(value, member.type)) {
            throw new VPNDetectionError(
                'server_error', `the answer's ${wire} is not ${TYPE_NAMES[member.type]}`, status,
            );
        }
        out[name] = value;
    }
    return out as T;
}

// Only a 4xx whose body is a JSON object with a STRING `error` is an OAuth
// refusal. Every 5xx, whatever it says, is the server failing, and is retried
// wherever the operation retries.
function throwIfFailed(res: Res): Response {
    if (res.response === undefined) {
        throw noResponse(res.error);
    }
    const { status, ok, headers } = res.response;
    if (ok) {
        return res.response;
    }
    const body = res.error;
    if (status >= 400 && status < 500 && isObject(body) && typeof body.error === 'string') {
        const description = typeof body.error_description === 'string' ? body.error_description : undefined;
        throw oauthErrorFrom(body.error, description, status);
    }
    throw errorFromResponse(status, headers, body);
}

function isObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const TYPE_NAMES: Record<Member['type'], string> = {
    'string': 'a string', 'integer': 'an integer', 'boolean': 'a boolean', 'string[]': 'a list of strings',
};

function hasType(value: unknown, type: Member['type']): boolean {
    if (type === 'string[]') {
        return Array.isArray(value) && value.every((item) => typeof item === 'string');
    }
    if (type === 'integer') {
        return Number.isInteger(value);
    }
    return typeof value === type;
}
