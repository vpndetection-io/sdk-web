// The members each answer must carry before the client hands it back: every one
// the spec requires and never sends as null. The tests read them against the
// generated types, so a member the spec adds fails the suite until it is here.

import { hasMembers } from './transport.js';

export const LOOKUP_MEMBERS = ['ip', 'is_vpn'] as const;
export const LOCATION_MEMBERS = [
    'continent', 'continent_name', 'country', 'country_name', 'timezone', 'currency_code', 'currency_name',
    'currency_symbol', 'flag_emoji', 'flag_unicode',
] as const;
export const ASN_MEMBERS = ['asn', 'name', 'domain', 'type', 'prefix'] as const;
export const BATCH_MEMBERS = ['results', 'errors'] as const;
export const BATCH_ERROR_MEMBERS = ['status', 'error'] as const;
export const ENTITLEMENT_MEMBERS = ['org_id', 'apikey', 'plan', 'usage'] as const;
export const ENTITLEMENT_APIKEY_MEMBERS = ['id', 'allowed_cidrs'] as const;
export const ENTITLEMENT_PLAN_MEMBERS = ['key', 'tier'] as const;
export const ENTITLEMENT_USAGE_MEMBERS = ['requests', 'quota', 'window_start', 'window_end'] as const;

// Every member's type, nullable and optional ones included: one the spec requires
// and never sends as null may not be null, and any other is null, absent or of its
// type. A `date` or `date-time` is RFC 3339's, on a day that exists. The tests hold
// each table to its generated type, and the date kinds to the spec's `format`.
type Kind = 'string' | 'integer' | 'boolean' | 'object' | 'array' | 'date' | 'date-time';

export const LOOKUP_TYPES: Record<string, Kind> = {
    ip: 'string', is_vpn: 'boolean', is_hosting: 'boolean', is_relay: 'boolean', is_tor: 'boolean',
    is_cdn: 'boolean', is_resproxy: 'boolean', is_dcproxy: 'boolean', is_mobproxy: 'boolean',
    is_pubproxy: 'boolean', vpn: 'object', hosting: 'object', relay: 'object', tor: 'object', cdn: 'object',
    resproxy: 'object', dcproxy: 'object', mobproxy: 'object', pubproxy: 'object', location: 'object',
    asn: 'object', trial_expired: 'boolean',
};
export const VPN_DETAIL_TYPES: Record<string, Kind> = {
    provider: 'string', last_seen: 'date', confidence: 'string', method: 'string',
};
export const CLASS_DETAIL_TYPES: Record<string, Kind> = {
    provider: 'string', confidence: 'string', last_seen: 'date',
};
export const PROXY_DETAIL_TYPES: Record<string, Kind> = {
    provider: 'string', first_seen: 'date', last_seen: 'date', hits: 'integer', hits_days_pct: 'integer',
    providers_num: 'integer',
};
export const PUBPROXY_DETAIL_TYPES: Record<string, Kind> = {
    entry: 'boolean', exit: 'boolean', protocols: 'array', num_ports: 'integer', num_proxies: 'integer',
    last_seen: 'date', last_usable: 'string',
};
export const LOCATION_TYPES: Record<string, Kind> = Object.fromEntries(
    LOCATION_MEMBERS.map((m) => [m, 'string'] as const),
);
export const ASN_TYPES: Record<string, Kind> = {
    asn: 'integer', name: 'string', domain: 'string', type: 'string', prefix: 'string',
};
export const BATCH_ERROR_TYPES: Record<string, Kind> = { status: 'integer', error: 'string' };
export const ENTITLEMENT_TYPES: Record<string, Kind> = {
    org_id: 'string', apikey: 'object', plan: 'object', usage: 'object',
};
export const ENTITLEMENT_APIKEY_TYPES: Record<string, Kind> = {
    id: 'string', expires: 'date-time', allowed_cidrs: 'array',
};
export const ENTITLEMENT_PLAN_TYPES: Record<string, Kind> = { key: 'string', tier: 'string' };
export const ENTITLEMENT_USAGE_TYPES: Record<string, Kind> = {
    requests: 'integer', quota: 'integer', hard_limit: 'integer', window_start: 'date-time',
    window_end: 'date-time',
};

function isObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isKind(value: unknown, kind: Kind): boolean {
    switch (kind) {
        case 'string': return typeof value === 'string';
        case 'integer': return Number.isInteger(value);
        case 'boolean': return typeof value === 'boolean';
        case 'object': return isObject(value);
        case 'array': return Array.isArray(value);
        case 'date': return typeof value === 'string' && isFullDate(value);
        case 'date-time': return typeof value === 'string' && isDateTime(value);
    }
}

const FULL_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))$/;

/** RFC 3339's `full-date`, naming a day its month has. */
function isFullDate(value: string): boolean {
    const m = FULL_DATE.exec(value);
    return m !== null && isDay(m[1]!, m[2]!, m[3]!);
}

/**
 * RFC 3339's `date-time`, its lowercase `t` and `z` included, with an hour below 24,
 * a minute and a second below 60 and an offset of at most 23:59.
 */
function isDateTime(value: string): boolean {
    const m = DATE_TIME.exec(value);
    return m !== null && isDay(m[1]!, m[2]!, m[3]!)
        && Number(m[4]) < 24 && Number(m[5]) < 60 && Number(m[6]) < 60
        && (m[7] === undefined || (Number(m[7]) < 24 && Number(m[8]) < 60));
}

// setUTCFullYear rather than Date.UTC, which reads a year below 100 as 19xx.
function isDay(year: string, month: string, day: string): boolean {
    const date = new Date(0);
    date.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    return date.getUTCFullYear() === Number(year) && date.getUTCMonth() === Number(month) - 1
        && date.getUTCDate() === Number(day);
}

function typed(
    value: unknown, required: readonly string[], types: Record<string, Kind>,
): value is Record<string, unknown> {
    return hasMembers(value, required) && Object.entries(types).every(([member, kind]) => {
        const v = value[member];
        return v === undefined || v === null ? !required.includes(member) : isKind(v, kind);
    });
}

function every(value: unknown, valid: (entry: unknown) => boolean): boolean {
    return Array.isArray(value) && value.every(valid);
}

function isString(value: unknown): boolean {
    return typeof value === 'string';
}

/** An optional member: absent or null, or valid. */
function optional(value: unknown, valid: (value: unknown) => boolean): boolean {
    return value === undefined || value === null || valid(value);
}

const DETAILS: [string, Record<string, Kind>][] = [
    ['vpn', VPN_DETAIL_TYPES], ['hosting', CLASS_DETAIL_TYPES], ['relay', CLASS_DETAIL_TYPES],
    ['tor', CLASS_DETAIL_TYPES], ['cdn', CLASS_DETAIL_TYPES], ['resproxy', PROXY_DETAIL_TYPES],
    ['dcproxy', PROXY_DETAIL_TYPES], ['mobproxy', PROXY_DETAIL_TYPES], ['pubproxy', PUBPROXY_DETAIL_TYPES],
];

export function isLookup(data: unknown): boolean {
    return typed(data, LOOKUP_MEMBERS, LOOKUP_TYPES)
        && DETAILS.every(([member, types]) => optional(data[member], (detail) => typed(detail, [], types)))
        && optional((data['pubproxy'] as Record<string, unknown> | undefined)?.['protocols'],
            (protocols) => every(protocols, isString))
        && optional(data['location'], (location) => typed(location, LOCATION_MEMBERS, LOCATION_TYPES))
        && optional(data['asn'], (asn) => typed(asn, ASN_MEMBERS, ASN_TYPES));
}

/** Both maps present. An entry in either is judged on its own, as that address's answer. */
export function isBatch(data: unknown): boolean {
    return hasMembers(data, BATCH_MEMBERS) && isObject(data['results']) && isObject(data['errors']);
}

export function isBatchError(entry: unknown): boolean {
    return typed(entry, BATCH_ERROR_MEMBERS, BATCH_ERROR_TYPES);
}

export function isEntitlement(data: unknown): boolean {
    return typed(data, ENTITLEMENT_MEMBERS, ENTITLEMENT_TYPES)
        && typed(data['apikey'], ENTITLEMENT_APIKEY_MEMBERS, ENTITLEMENT_APIKEY_TYPES)
        && every((data['apikey'] as Record<string, unknown>)['allowed_cidrs'], isString)
        && typed(data['plan'], ENTITLEMENT_PLAN_MEMBERS, ENTITLEMENT_PLAN_TYPES)
        && typed(data['usage'], ENTITLEMENT_USAGE_MEMBERS, ENTITLEMENT_USAGE_TYPES);
}
