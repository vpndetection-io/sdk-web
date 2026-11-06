import type { LookupResponse } from './generated/types.gen.js';
import { isLookup } from './shapes.js';
import { toResult, type Result } from './types.js';

/**
 * A persistent tier behind the client's in-memory cache, for answers that should
 * outlive the client: a page reload, or an extension's service worker, which the
 * browser stops once it sits idle and starts again on the next event.
 *
 * `key` is the address with a hash of the client's API key and base URL in front of
 * it, so clients holding different keys, and so entitled to different fields, can
 * share one store without ever reading each other's answers. `set` is handed how long
 * the answer stays fresh; dropping it once that has passed is the store's job.
 */
export interface CacheStore {
    get(key: string): Promise<Result | undefined> | Result | undefined;
    set(key: string, result: Result, ttlMs: number): Promise<void> | void;
}

/**
 * The client's side of a `CacheStore`. A store is a cache, never a source of
 * errors: one that throws or rejects reads as a miss and a write that fails is
 * dropped, so either costs a request and never an answer. An entry it hands back
 * is read the way an answer off the wire is, so one that is not a lookup answer
 * is a miss too.
 */
export class StoreTier {
    constructor(
        private readonly store: CacheStore,
        private readonly scope: string,
        private readonly ttlMs: number,
    ) {}

    async get(ip: string): Promise<Result | undefined> {
        let stored: unknown;
        try {
            stored = await this.store.get(this.keyFor(ip));
        } catch {
            return undefined;
        }
        if (typeof stored !== 'object' || stored === null) {
            return undefined;
        }
        const raw = (stored as { raw?: unknown }).raw;
        return isLookup(raw) ? toResult(raw as LookupResponse) : undefined;
    }

    async set(ip: string, result: Result): Promise<void> {
        try {
            await this.store.set(this.keyFor(ip), result, this.ttlMs);
        } catch {
            // Costs a request on the next miss, nothing more.
        }
    }

    private keyFor(ip: string): string {
        return `${this.scope}:${ip}`;
    }
}

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK_64 = (1n << 64n) - 1n;

/**
 * What tells one client's entries from another's: FNV-1a over the base URL and the
 * key, as 16 hex digits. It tells keys apart and keeps the key itself out of the
 * store; it is not a way to keep a key secret.
 */
export function storeScope(baseUrl: string, apiKey: string | undefined): string {
    let hash = FNV_OFFSET;
    for (const byte of new TextEncoder().encode(`${baseUrl}\n${apiKey ?? ''}`)) {
        hash = ((hash ^ BigInt(byte)) * FNV_PRIME) & MASK_64;
    }
    return hash.toString(16).padStart(16, '0');
}

/** A store is two functions; anything else is refused where the client is built. */
export function isCacheStore(store: unknown): store is CacheStore {
    return typeof store === 'object' && store !== null
        && typeof (store as CacheStore).get === 'function' && typeof (store as CacheStore).set === 'function';
}
