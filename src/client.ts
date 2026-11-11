import { LRUCache } from 'lru-cache';
import pLimit from 'p-limit';

import { createClient, createConfig } from './generated/client/index.js';
import type { Client } from './generated/client/index.js';
import { lookupBatch, lookupIp, lookupMyIp, myEntitlement } from './generated/sdk.gen.js';
import type { BatchLookupResponse, Entitlement, LookupResponse } from './generated/types.gen.js';

import { bogonResult, isBogon, unmapped } from './bogon.js';
import { errorFromEntry, VPNDetectionError } from './errors.js';
import { OauthApi } from './oauth.js';
import { isBatch, isBatchError, isEntitlement, isLookup } from './shapes.js';
import { isCacheStore, storeScope, StoreTier, type CacheStore } from './store.js';
import {
    asError, checkConcurrency, checkRetries, checkTimeout, deadline, readable, withRetry,
} from './transport.js';
import { toResult, type Result } from './types.js';

export const DEFAULT_BASE_URL = 'https://api.vpndetection.io';

// fetch has no whole-request limit of its own, so without this a hung API would
// hold a caller for as long as the browser keeps the connection open.
const DEFAULT_TIMEOUT_MS = 30_000;

// The most addresses POST /batch takes in one call; a larger batch is sent in
// chunks of this size.
const BATCH_MAX = 1000;

export interface CacheOptions {
    /** Maximum number of addresses held in memory. Default 10000. */
    max?: number;
    /** How long an answer stays fresh, in milliseconds. Default 1 hour. */
    ttlMs?: number;
    /**
     * Where answers outlive this client: read after the in-memory cache misses and
     * before the network, and written after each answer the API serves. Bogons,
     * errors, `myIp` and `myEntitlement` are never stored.
     */
    store?: CacheStore;
}

export interface Options {
    /**
     * Your API key. Omit it to look up without one: a lookup then answers
     * `ip`, `is_vpn`, the Tor and relay members, `location` and `asn`, with no
     * daily or monthly cap, and a batch is refused as `unauthorized`.
     * A key in a web page is readable by anyone who opens the page.
     */
    apiKey?: string;
    baseUrl?: string;
    /** Pass `false` to disable caching. */
    cache?: CacheOptions | false;
    /** Concurrent batch requests - chunks of up to 1000 addresses - during a batch. Default 8. */
    concurrency?: number;
    /** Retry attempts for a transient failure, a whole number from 0. Default 2. */
    retries?: number;
    /**
     * How long one request may take before it is abandoned, in milliseconds.
     * Default 30000. Applies per attempt, so a retried call may take longer in
     * total.
     */
    timeoutMs?: number;
    /** Override the HTTP implementation, mostly for tests. Defaults to the global `fetch`. */
    fetch?: typeof globalThis.fetch;
}

/** Per-call overrides for a single lookup. Anything omitted falls back to the client's setting. */
export interface LookupOptions {
    /** Retry attempts for a transient failure, a whole number from 0. */
    retries?: number;
    /** How long one attempt may take before it is abandoned, in milliseconds. */
    timeoutMs?: number;
}

/** Per-call overrides for one batch. Anything omitted falls back to the client's setting. */
export interface BatchOptions extends LookupOptions {
    /** Concurrent batch requests for THIS batch only. */
    concurrency?: number;
}

/**
 * A client for the VPNDetection API, for a browser: a page's own scripts, a web
 * worker or an extension.
 *
 * The cache is per instance, so an answer is never shared between two clients
 * holding different API keys and therefore entitled to different fields.
 */
export class VPNDetection {
    private readonly client: Client;
    // Keyed by address. The context is how a call sends the request when the
    // address has none in flight: `fetch()` runs it synchronously, so a batch
    // knows which addresses it leads before it builds a chunk.
    private readonly cache: LRUCache<string, Result, () => Promise<Result>> | null;
    private readonly store: StoreTier | null;
    private readonly limit: ReturnType<typeof pLimit>;
    private readonly retries: number;
    private readonly timeoutMs: number;

    /**
     * Sign a person in through their browser with the OAuth authorization code
     * flow and PKCE. Needs no API key.
     */
    readonly oauth: OauthApi;

    constructor(options: Options = {}) {
        const apiKey = checkApiKey(options.apiKey);
        // Every path appended starts with a slash, and a second one is another
        // path, which the API answers with a redirect.
        const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
        this.client = createClient(createConfig({
            baseUrl: baseUrl,
            ...(apiKey === undefined ? {} : { auth: bearerOnly(apiKey) }),
            // Looked up on each request rather than bound here, so a script that wraps
            // the page's fetch after this client is built still sees its requests.
            fetch: options.fetch ?? ((input, init) => globalThis.fetch(input, init)),
        }));
        this.retries = checkRetries(options.retries) ?? 2;
        this.timeoutMs = checkTimeout(options.timeoutMs) ?? DEFAULT_TIMEOUT_MS;
        this.limit = pLimit(checkConcurrency(options.concurrency) ?? 8);

        const cache = options.cache === false ? null : (options.cache ?? {});
        const ttlMs = cache?.ttlMs ?? 60 * 60 * 1000;
        this.cache = cache === null ? null : new LRUCache<string, Result, () => Promise<Result>>({
            max: cache.max ?? 10_000,
            ttl: ttlMs,
            // Concurrent misses for one address share one request: every
            // `fetch()` while it is in flight gets the same promise, and a
            // failure rejects them all and is cached for none.
            fetchMethod: (_ip, _stale, { context }) => context(),
            // An eviction must not fail the callers awaiting a request.
            ignoreFetchAbort: true,
        });
        // `null` is no store, as it is no key.
        const store = cache?.store ?? undefined;
        if (store !== undefined && !isCacheStore(store)) {
            throw new VPNDetectionError('bad_request', 'cache.store must have a get and a set function');
        }
        this.store = store === undefined ? null : new StoreTier(store, storeScope(baseUrl, apiKey), ttlMs);
        this.oauth = new OauthApi(this.client, this.retries, this.timeoutMs);
    }

    /**
     * Whether an address is private, loopback, link-local, documentation,
     * multicast or otherwise not routable, including the IPv6 equivalents and
     * the 6to4 and Teredo ranges.
     *
     * These are the addresses `lookup` answers locally. Exposed here so the
     * check is reachable from the client you already hold; the same function is
     * also importable on its own.
     */
    isBogon(ip: string): boolean {
        return isBogon(ip);
    }

    /**
     * Classify one address.
     *
     * A bogon is answered locally and never reaches the network. Everything
     * else is served, then cached for this instance, and kept in the cache's
     * `store` when it has one. Calls that miss the cache while a request for
     * their address is in flight, a batch's included, await that request rather
     * than sending their own, and take its answer, sent under the options of the
     * call that led it. An IPv4-mapped address (`::ffff:8.8.8.8`) is the IPv4
     * address it carries: judged, sent and cached as that, so the answer names
     * `8.8.8.8`.
     */
    async lookup(ip: string, options: LookupOptions = {}): Promise<Result> {
        // First, or a bogon and a cached address would answer any value.
        checkTimeout(options.timeoutMs);
        checkRetries(options.retries);
        const addr = unmapped(ip);
        if (isBogon(addr)) {
            return bogonResult(addr);
        }
        if (this.cache === null) {
            return this.serve(addr, options);
        }
        return (await this.cache.fetch(addr, { context: () => this.answer(addr, options) }))!;
    }

    // A miss in memory: the store's answer if it holds one, else the API's, kept.
    private async answer(ip: string, options: LookupOptions): Promise<Result> {
        const stored = await this.store?.get(ip);
        if (stored !== undefined) {
            return stored;
        }
        const served = await this.serve(ip, options);
        await this.store?.set(ip, served);
        return served;
    }

    private async serve(ip: string, options: LookupOptions): Promise<Result> {
        const timeoutMs = options.timeoutMs ?? this.timeoutMs;
        return withRetry(options.retries ?? this.retries, async () => {
            const res = await deadline(timeoutMs, (signal) => lookupIp({
                client: this.client, path: { ip: ip }, signal: signal,
            }));
            return toResult(readable<LookupResponse>(res, isLookup));
        });
    }

    /**
     * Classify the address this client is calling from: in a page, the visitor's
     * own.
     *
     * The same answer `lookup` would give for that address, at the same cost
     * against your allowance. The address is the one our edge observed, so a
     * call made through a proxy or a VPN reports the exit it left through -
     * usually the point of asking.
     *
     * Deliberately NOT cached. The cache is keyed by address, and which
     * address this is IS the question: a device that moves between networks
     * would otherwise be told where it used to be.
     */
    async myIp(options: LookupOptions = {}): Promise<Result> {
        const timeoutMs = checkTimeout(options.timeoutMs) ?? this.timeoutMs;
        return withRetry(checkRetries(options.retries) ?? this.retries, async () => {
            const res = await deadline(timeoutMs, (signal) => lookupMyIp({
                client: this.client, signal: signal,
            }));
            return toResult(readable<LookupResponse>(res, isLookup));
        });
    }

    /**
     * What this client's key is entitled to, and how much of it has been used.
     *
     * Named for what it answers rather than `me`, which sits one letter from
     * `myIp` and means something quite different: one is which address you are
     * calling FROM, the other is what the key you are calling WITH may spend.
     *
     * Unlike a lookup there is no useful unauthenticated answer, so a client
     * built without a key gets an unauthorized error rather than a partial one.
     *
     * Usage counts against the ALLOWANCE WINDOW - the anniversary of the
     * subscription, not the calendar month and not the billing period - and it
     * is the same number a lookup is gated on. It can lag by a few seconds,
     * because requests are counted in memory and flushed in aggregate.
     *
     * Deliberately NOT cached: the whole point is what has been spent, and a
     * cached answer is a wrong one within seconds of the next request.
     */
    async myEntitlement(options: LookupOptions = {}): Promise<Entitlement> {
        const timeoutMs = checkTimeout(options.timeoutMs) ?? this.timeoutMs;
        return withRetry(checkRetries(options.retries) ?? this.retries, async () => {
            const res = await deadline(timeoutMs, (signal) => myEntitlement({
                client: this.client, signal: signal,
            }));
            return readable<Entitlement>(res, isEntitlement);
        });
    }

    /**
     * Classify many addresses in as few requests as possible.
     *
     * Bogons are answered locally, cached answers are reused, the cache's `store`
     * is read for the rest, and an address with a request already in flight, a
     * lookup's or another batch's, awaits that request; everything else goes to
     * the batch endpoint in chunks of up to 1000 addresses, with at most
     * `concurrency` chunks in flight, and a lookup arriving meanwhile awaits this
     * batch's answer for its address. Keyed by address rather than positional, so
     * duplicates in the input collapse to a single entry and the caller never has
     * to line two lists up. An address that fails carries its error as its value,
     * so one bad entry cannot lose the rest of the answers: the API reports a
     * per-entry failure with the status the single lookup would have answered,
     * and a chunk that fails as a whole marks every address in it. A per-call
     * `concurrency` below 1 is refused as `bad_request` before anything is sent.
     * An IPv4-mapped address is looked up as the IPv4 address it carries, and its
     * answer keyed as you passed it. The batch endpoint needs an API key, a free
     * one included: without one, every address sent to it carries an
     * `unauthorized` error.
     */
    async lookupBatch(
        ips: Iterable<string>, options: BatchOptions = {},
    ): Promise<Map<string, Result | VPNDetectionError>> {
        const concurrency = checkConcurrency(options.concurrency);
        checkTimeout(options.timeoutMs);
        checkRetries(options.retries);
        const asked = [...new Set(ips)];
        const unique = [...new Set(asked.map(unmapped))];
        const out = new Map<string, Result | VPNDetectionError>();
        const pending: string[] = [];
        // Every address that is neither a bogon nor cached goes through
        // `fetch()` in one synchronous pass: one with a request in flight joins
        // it, and for the rest `fetchMethod` runs at once, which is how this
        // batch learns the addresses it leads before building any chunk.
        const shared: [string, Promise<Result | undefined>][] = [];
        const led = new Map<string, Deferred<Result>>();
        for (const ip of unique) {
            if (isBogon(ip)) {
                out.set(ip, bogonResult(ip));
                continue;
            }
            const hit = this.cache?.get(ip);
            if (hit !== undefined) {
                out.set(ip, hit);
                continue;
            }
            if (this.cache === null) {
                pending.push(ip);
                continue;
            }
            shared.push([ip, this.cache.fetch(ip, {
                context: () => {
                    const landing = deferred<Result>();
                    led.set(ip, landing);
                    pending.push(ip);
                    return landing.promise;
                },
            })]);
        }
        const sending = this.store === null ? pending : await this.unstored(pending, led);
        // A per-call concurrency gets its own limiter; without one the call
        // would share the instance's budget and silently ignore the override.
        const limit = concurrency === undefined ? this.limit : pLimit(concurrency);
        const chunks: string[][] = [];
        for (let i = 0; i < sending.length; i += BATCH_MAX) {
            chunks.push(sending.slice(i, i + BATCH_MAX));
        }
        await Promise.all([
            ...chunks.map((chunk) => limit(async () => {
                const kept: Promise<void>[] = [];
                for (const [ip, answer] of await this.lookupChunk(chunk, options)) {
                    const landing = led.get(ip);
                    if (landing === undefined) {
                        out.set(ip, answer);
                    } else if (answer instanceof VPNDetectionError) {
                        landing.reject(answer);
                    } else {
                        landing.resolve(answer);
                    }
                    if (this.store !== null && !(answer instanceof VPNDetectionError)) {
                        kept.push(this.store.set(ip, answer));
                    }
                }
                await Promise.all(kept);
            })),
            ...shared.map(async ([ip, answer]) => {
                try {
                    out.set(ip, (await answer)!);
                } catch (err) {
                    out.set(ip, asError(err));
                }
            }),
        ]);
        // Reinstated in input order, under the addresses as passed: chunks
        // settle in completion order, and a caller iterating the map should see
        // what they passed in.
        return new Map(asked.map((ip) => [ip, out.get(unmapped(ip))!]));
    }

    // The addresses this batch leads that the store does not hold, in the order
    // given. One the store holds lands at once, as a request's answer would.
    private async unstored(ips: string[], led: Map<string, Deferred<Result>>): Promise<string[]> {
        const stored = await Promise.all(ips.map((ip) => this.store!.get(ip)));
        return ips.filter((ip, i) => {
            const hit = stored[i];
            if (hit === undefined) {
                return true;
            }
            led.get(ip)!.resolve(hit);
            return false;
        });
    }

    // One POST /batch, mapped back onto the addresses it was asked about. A
    // chunk-level failure - the call refused, the transport failing, the
    // retries exhausted - becomes every address's error, exactly as it would
    // have been had each been looked up alone.
    private async lookupChunk(
        chunk: string[], options: LookupOptions,
    ): Promise<Map<string, Result | VPNDetectionError>> {
        const out = new Map<string, Result | VPNDetectionError>();
        const timeoutMs = options.timeoutMs ?? this.timeoutMs;
        let body: BatchLookupResponse;
        try {
            body = await withRetry(options.retries ?? this.retries, async () => {
                const res = await deadline(timeoutMs, (signal) => lookupBatch({
                    client: this.client, body: { ips: chunk }, signal: signal,
                }));
                return readable<BatchLookupResponse>(res, isBatch);
            });
        } catch (err) {
            const failure = asError(err);
            for (const ip of chunk) {
                out.set(ip, failure);
            }
            return out;
        }
        // An entry is judged alone: one the client cannot read is that address's
        // error, and the rest of the chunk keeps its answers. Each map is read by
        // its own keys alone, so an address spelled `__proto__`, `constructor` or
        // `toString` never reads the object's prototype as an answer.
        for (const ip of chunk) {
            const served = Object.hasOwn(body.results, ip) ? body.results[ip] : undefined;
            if (served !== undefined) {
                out.set(ip, isLookup(served) ? toResult(served) : unreadableEntry(ip));
                continue;
            }
            const failed = Object.hasOwn(body.errors, ip) ? body.errors[ip] : undefined;
            if (failed !== undefined) {
                out.set(ip, isBatchError(failed) ? errorFromEntry(failed) : unreadableEntry(ip));
                continue;
            }
            out.set(ip, new VPNDetectionError(
                'server_error', `the batch answer did not include ${ip}`, 200,
            ));
        }
        return out;
    }
}

interface Deferred<T> {
    promise: Promise<T>;
    resolve(value: T): void;
    reject(reason: unknown): void;
}

// Promise.withResolvers by hand: it is newer than the browsers this library supports.
function deferred<T>(): Deferred<T> {
    let resolve!: (value: T) => void;
    let reject!: (reason: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise: promise, resolve: resolve, reject: reject };
}

/**
 * The key without the blanks around it, and no key at all for blanks alone,
 * which would go out as `Authorization: Bearer`. A control character inside it
 * is refused here, since fetch refuses such a header and every call would fail
 * with nothing sent. `null` is no key.
 */
function checkApiKey(apiKey: unknown): string | undefined {
    if (apiKey === undefined || apiKey === null) {
        return undefined;
    }
    if (typeof apiKey !== 'string') {
        throw new VPNDetectionError('bad_request', `apiKey must be a string, got ${typeof apiKey}`);
    }
    const key = apiKey.trim();
    if (/[\u0000-\u001f\u007f]/.test(key)) {
        throw new VPNDetectionError('bad_request', 'apiKey must not contain a control character');
    }
    // fetch sends a header as Latin-1 and refuses anything past it.
    if (/[^\u0000-\u00ff]/.test(key)) {
        throw new VPNDetectionError('bad_request', 'apiKey must not contain a character past U+00FF');
    }
    return key === '' ? undefined : key;
}

function unreadableEntry(ip: string): VPNDetectionError {
    return new VPNDetectionError('server_error', `unreadable batch answer for ${ip}, status 200`, 200);
}

/**
 * Sends the key in the `Authorization` header and nowhere else.
 *
 * The API accepts three credential forms and the spec documents all three, so
 * the generator applies EVERY one of them - putting the key in the query string
 * of every request alongside the headers. A query string is the one place a
 * secret should never be: it lands in access logs, proxy logs and browser
 * history, none of which we control.
 *
 * Returning undefined for the other schemes is what suppresses them; the
 * generated `getAuthToken` drops a scheme whose callback yields nothing.
 */
function bearerOnly(apiKey: string): (auth: { scheme?: string }) => string | undefined {
    return (auth) => (auth.scheme === 'bearer' ? apiKey : undefined);
}
