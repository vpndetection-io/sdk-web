import type {
    AbuseContact, Asn, BitTorrentDetail, CarrierDetail, ClassDetail, Company, DnsResolverDetail, Location,
    LookupResponse, ProxyDetail, PubproxyDetail, SatelliteDetail, SmtpDetail, SshDetail, VpnDetail, WebDetail,
} from './generated/types.gen.js';

export type {
    AbuseContact, Asn, BitTorrentDetail, CarrierDetail, ClassDetail, Company, DnsResolverDetail, Location,
    LookupResponse, ProxyDetail, PubproxyDetail, SatelliteDetail, SmtpDetail, SshDetail, VpnDetail, WebDetail,
};

/**
 * What a lookup answers.
 *
 * An **optional** member is one your plan does not include. It never means "we
 * could not check", so `undefined` and `false` are genuinely different answers:
 * `undefined` is "not in your plan", `false` is "checked, and no". Use
 * `?? false` when you only care whether the address is flagged. The same holds
 * inside `location` and `asn`, whose paid members are absent on Unlimited.
 *
 * A detail object that is present but empty (`{}`, and `web`'s `[]`) means the
 * flag above it is false. A populated one always carries every one of its keys.
 */
export interface Result {
    /** The address that was looked up, normalized. */
    ip: string;
    /** Whether the address is VPN infrastructure. Every plan includes this. */
    isVpn: boolean;
    /**
     * Whether the address is reserved space (private, loopback, documentation and the like), which
     * this package answers locally without a request. A served answer carries the API's own `is_bogon`.
     */
    isBogon: boolean;

    isHosting?: boolean;
    isRelay?: boolean;
    isTor?: boolean;
    isCdn?: boolean;
    isResproxy?: boolean;
    isDcproxy?: boolean;
    isMobproxy?: boolean;
    isPubproxy?: boolean;
    /** Whether the address is announced from many places at once. Every plan includes this. */
    isAnycast?: boolean;
    isCarrier?: boolean;
    isSatellite?: boolean;
    isSsh?: boolean;
    isSmtp?: boolean;
    isWeb?: boolean;
    isDnsResolver?: boolean;
    isBittorrent?: boolean;
    /**
     * On answers to a key on the free plan only: `false` while its organization's trial of every
     * field lasts, `true` once the answer has Unlimited's.
     */
    trialExpired?: boolean;
    /**
     * On answers to a key on a paid plan only: `false` while the answer has every field, `true`
     * once its organization's overage cap is reached and the answer has Unlimited's. Lookups
     * answered past the cap are not billed.
     */
    capReached?: boolean;

    vpn?: VpnDetail;
    hosting?: ClassDetail;
    relay?: ClassDetail;
    tor?: ClassDetail;
    cdn?: ClassDetail;
    resproxy?: ProxyDetail;
    dcproxy?: ProxyDetail;
    mobproxy?: ProxyDetail;
    pubproxy?: PubproxyDetail;
    carrier?: CarrierDetail;
    satellite?: SatelliteDetail;
    ssh?: SshDetail;
    smtp?: SmtpDetail;
    /** A row per port that answered, lowest first. */
    web?: WebDetail[];
    dnsResolver?: DnsResolverDetail;
    bittorrent?: BitTorrentDetail;

    /**
     * Where the address is, on every answer, with or without a key: every key present, empty
     * strings where it is not known. The region, city, postal code, coordinates and the rest
     * after `flag_unicode` come with a paid plan.
     */
    location?: Location;
    /**
     * The AS announcing the address, on every answer, with or without a key: `asn` is 0 where none
     * does. `country` and `rpki_status` are on every plan too.
     */
    asn?: Asn;
    /** The organization the address is assigned to. */
    company?: Company;
    /**
     * The name the address's reverse DNS (PTR) record points to, empty when it has none. Every
     * plan includes this.
     */
    hostname?: string;
    /** Where to report abuse from the address. */
    abuse?: AbuseContact;

    /** The response exactly as it came off the wire, with its original names. */
    raw: LookupResponse;
}

// The one place the wire's snake_case becomes idiomatic camelCase. Every member
// is copied when its key is PRESENT rather than truthy, so a plan that includes a
// field and answers `false` keeps it, and a plan that does not include it stays
// undefined. A member the spec adds fails to compile here until it is named.
const RESULT_NAMES: Record<Exclude<keyof LookupResponse, 'is_bogon'>, Exclude<keyof Result, 'raw' | 'isBogon'>> = {
    ip: 'ip', is_vpn: 'isVpn', is_hosting: 'isHosting', is_relay: 'isRelay', is_tor: 'isTor', is_cdn: 'isCdn',
    is_resproxy: 'isResproxy', is_dcproxy: 'isDcproxy', is_mobproxy: 'isMobproxy', is_pubproxy: 'isPubproxy',
    is_anycast: 'isAnycast', is_carrier: 'isCarrier', is_satellite: 'isSatellite', is_ssh: 'isSsh',
    is_smtp: 'isSmtp', is_web: 'isWeb', is_dns_resolver: 'isDnsResolver', is_bittorrent: 'isBittorrent',
    trial_expired: 'trialExpired', cap_reached: 'capReached',
    vpn: 'vpn', hosting: 'hosting', relay: 'relay', tor: 'tor', cdn: 'cdn', resproxy: 'resproxy', dcproxy: 'dcproxy',
    mobproxy: 'mobproxy', pubproxy: 'pubproxy', carrier: 'carrier', satellite: 'satellite', ssh: 'ssh', smtp: 'smtp',
    web: 'web', dns_resolver: 'dnsResolver', bittorrent: 'bittorrent', location: 'location', asn: 'asn',
    company: 'company', hostname: 'hostname', abuse: 'abuse',
};

export function toResult(body: LookupResponse): Result {
    const out: Record<string, unknown> = {};
    for (const [from, to] of Object.entries<string>(RESULT_NAMES)) {
        if (from in body && body[from as keyof LookupResponse] !== undefined) {
            out[to] = body[from as keyof LookupResponse];
        }
    }
    out['isBogon'] = body.is_bogon === true;
    out['raw'] = body;
    return out as unknown as Result;
}
