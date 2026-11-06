import { BOGON_V4, BOGON_V6 } from './bogons.gen.js';
import type { LookupResponse } from './generated/types.gen.js';
import type { Result } from './types.js';

/**
 * Whether an address is a bogon: private, loopback, link-local, documentation,
 * multicast or otherwise not routable on the public internet, including the
 * IPv6 equivalents and the 6to4 and Teredo ranges that wrap them.
 *
 * These can never be VPN or proxy infrastructure, so the client answers them
 * itself and they never cost a request. An IPv4-mapped address
 * (`::ffff:8.8.8.8`) is judged as the IPv4 address it carries.
 */
export function isBogon(ip: string): boolean {
    const addr = unmapped(ip);
    if (addr.includes(':')) {
        const a = v6ToInt(addr);
        return a === null ? false : v6().some((r) => (a & r.mask) === r.net);
    }
    const a = v4ToInt(addr);
    return a === null ? false : v4().some((r) => (a & r.mask) >>> 0 === r.net);
}

/**
 * The IPv4 address an IPv4-mapped IPv6 address carries, dotted, and any other
 * string as given. A server listening on `::` sees every IPv4 visitor in the
 * mapped form, which is inside `::ffff:0:0/96` and so read whole would answer
 * every one of them as a bogon, with no request made.
 */
export function unmapped(ip: string): string {
    if (!ip.includes(':')) {
        return ip;
    }
    const a = v6ToInt(ip);
    if (a === null || a >> 32n !== 0xffffn) {
        return ip;
    }
    const n = Number(a & 0xffffffffn);
    return [n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

/**
 * The answer a bogon gets, in the full shape the API serves at its widest plan:
 * every flag present and false, every detail object present and empty, and
 * `location` and `asn` with every key empty, as the API answers a bogon.
 *
 * `isBogon` is set so a caller can always tell a locally computed answer from a
 * served one. Note this is deliberately the WIDEST shape regardless of your
 * plan, so do not infer which fields your plan includes from a bogon answer.
 */
export function bogonResult(ip: string): Result {
    return {
        ip: ip,
        isBogon: true,
        isVpn: false,
        isHosting: false,
        isRelay: false,
        isTor: false,
        isCdn: false,
        isResproxy: false,
        isDcproxy: false,
        isMobproxy: false,
        isPubproxy: false,
        vpn: {},
        hosting: {},
        relay: {},
        tor: {},
        cdn: {},
        resproxy: {},
        dcproxy: {},
        mobproxy: {},
        pubproxy: {},
        location: {
            continent: '',
            continent_name: '',
            country: '',
            country_name: '',
            timezone: '',
            currency_code: '',
            currency_name: '',
            currency_symbol: '',
            flag_emoji: '',
            flag_unicode: '',
        },
        asn: { asn: 0, name: '', domain: '', type: '', prefix: '' },
        raw: {} as LookupResponse,
    };
}

// Parsed once on first use rather than at import: a consumer that never looks
// up an address should not pay for the table, and module-scope work is what
// makes a library expensive to import.
let v4Cache: { net: number, mask: number }[] | null = null;
let v6Cache: { net: bigint, mask: bigint }[] | null = null;

function v4() {
    if (!v4Cache) {
        v4Cache = BOGON_V4.map((c) => {
            const [net, bits] = c.split('/');
            const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
            return { net: ((v4ToInt(net) as number) & mask) >>> 0, mask: mask };
        });
    }
    return v4Cache;
}

function v6() {
    if (!v6Cache) {
        v6Cache = BOGON_V6.map((c) => {
            const [net, bits] = c.split('/');
            const mask = bits === '0' ? 0n : (~0n << BigInt(128 - Number(bits))) & MAX128;
            return { net: (v6ToInt(net) as bigint) & mask, mask: mask };
        });
    }
    return v6Cache;
}

const MAX128 = (1n << 128n) - 1n;

function v4ToInt(ip: string): number | null {
    const p = ip.split('.');
    if (p.length !== 4) {
        return null;
    }
    let n = 0;
    for (const part of p) {
        const b = Number(part);
        if (!Number.isInteger(b) || b < 0 || b > 255 || part === '') {
            return null;
        }
        n = ((n << 8) | b) >>> 0;
    }
    return n;
}

// Handles the `::` run and a trailing IPv4 literal (::ffff:1.2.3.4), which
// several of the canonical ranges use.
function v6ToInt(ip: string): bigint | null {
    let a = ip;
    const v4Tail = a.match(/(\d+\.\d+\.\d+\.\d+)$/);
    if (v4Tail) {
        const n = v4ToInt(v4Tail[1]);
        if (n === null) {
            return null;
        }
        const hi = (n >>> 16).toString(16).padStart(4, '0');
        const lo = (n & 0xffff).toString(16).padStart(4, '0');
        a = `${a.slice(0, v4Tail.index)}${hi}:${lo}`;
    }
    const dbl = a.indexOf('::');
    let groups: string[];
    if (dbl === -1) {
        groups = a.split(':');
        if (groups.length !== 8) {
            return null;
        }
    } else {
        const head = a.slice(0, dbl).split(':').filter((g) => g !== '');
        const tail = a.slice(dbl + 2).split(':').filter((g) => g !== '');
        const fill = 8 - head.length - tail.length;
        if (fill < 0) {
            return null;
        }
        groups = [...head, ...Array(fill).fill('0'), ...tail];
    }
    let n = 0n;
    for (const g of groups) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
            return null;
        }
        n = (n << 16n) | BigInt(parseInt(g, 16));
    }
    return n;
}
