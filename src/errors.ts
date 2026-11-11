/**
 * Why a request failed.
 *
 * `rate_limited` and `quota_exceeded` both arrive as HTTP 429 and are NOT the
 * same thing. A rate limit is the API protecting itself, or a lookup without
 * a key past 60 a minute, and carries `Retry-After`; retrying works. A spent
 * quota carries no such header and retrying will not help until the window
 * rolls over or the limit is raised. The header is the only thing that
 * distinguishes them.
 */
export type ErrorKind =
    | 'bad_request'
    | 'unauthorized'
    | 'forbidden'
    | 'rate_limited'
    | 'quota_exceeded'
    | 'server_error'
    | 'network';

export class VPNDetectionError extends Error {
    readonly kind: ErrorKind;
    readonly status?: number;
    readonly retryAfterSeconds?: number;

    constructor(kind: ErrorKind, message: string, status?: number, retryAfterSeconds?: number) {
        super(message);
        this.name = 'VPNDetectionError';
        this.kind = kind;
        this.status = status;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    /** Whether retrying this exact request could succeed. */
    get retryable(): boolean {
        return this.kind === 'rate_limited' || this.kind === 'server_error' || this.kind === 'network';
    }
}

/**
 * The authorization server refusing an OAuth request: a 4xx whose body names an
 * OAuth error code. Never retryable as it stands.
 *
 * `kind` follows the status like any other failure's. A 401 here means the
 * client ID is not registered, never the API key, which OAuth requests do not
 * carry. The two codes a sign-in ends on have their own subclasses.
 */
export class OauthError extends VPNDetectionError {
    /** The server's code, such as `invalid_grant` or `invalid_client`, kept as sent. */
    readonly errorCode: string;
    /** The server's explanation, when it sent one. */
    readonly errorDescription?: string;

    constructor(errorCode: string, errorDescription?: string, status?: number) {
        super(
            status === undefined ? 'bad_request' : errorFromResponse(status, NO_HEADERS, undefined).kind,
            errorDescription === undefined ? errorCode : `${errorCode}: ${errorDescription}`,
            status,
        );
        this.name = 'OauthError';
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    override get retryable(): boolean {
        return false;
    }
}

/** The person refused the sign-in, so a new attempt starts over. */
export class OauthAccessDeniedError extends OauthError {
    constructor(errorDescription?: string, status?: number) {
        super('access_denied', errorDescription, status);
        this.name = 'OauthAccessDeniedError';
    }
}

/** What was presented is no longer valid: it expired, or was already used or refused. */
export class OauthExpiredTokenError extends OauthError {
    constructor(errorDescription?: string, status?: number) {
        super('expired_token', errorDescription, status);
        this.name = 'OauthExpiredTokenError';
    }
}

export function oauthErrorFrom(
    errorCode: string, errorDescription: string | undefined, status: number,
): OauthError {
    if (errorCode === 'access_denied') {
        return new OauthAccessDeniedError(errorDescription, status);
    }
    if (errorCode === 'expired_token') {
        return new OauthExpiredTokenError(errorDescription, status);
    }
    return new OauthError(errorCode, errorDescription, status);
}

const NO_HEADERS = { get: () => null };

export function errorFromResponse(
    status: number, headers: { get(name: string): string | null }, body: unknown,
): VPNDetectionError {
    const message = messageOf(body) ?? `request failed with status ${status}`;
    const retryAfter = parseRetryAfter(headers.get('retry-after'));

    if (status === 429) {
        // Present means transient, absent means an allowance is spent. Nothing
        // else in the response separates the two.
        return retryAfter === undefined
            ? new VPNDetectionError('quota_exceeded', message, status)
            : new VPNDetectionError('rate_limited', message, status, retryAfter);
    }
    if (status === 400) {
        return new VPNDetectionError('bad_request', message, status);
    }
    if (status === 401) {
        return new VPNDetectionError('unauthorized', message, status);
    }
    if (status === 403) {
        return new VPNDetectionError('forbidden', message, status);
    }
    // Any other 4xx is a CLIENT error. Falling through to the server_error
    // default would make it retryable. Only 5xx and transport failures are
    // worth a retry.
    if (status < 500) {
        return new VPNDetectionError('bad_request', message, status);
    }
    return new VPNDetectionError('server_error', message, status);
}

/**
 * A per-entry failure inside a successful batch: the status the single lookup
 * would have answered, and its message, with no headers at all - so a 429 here
 * is a spent allowance, which is the only kind the API puts in an entry.
 */
export function errorFromEntry(entry: { status: number, error: string }): VPNDetectionError {
    return errorFromResponse(entry.status, NO_HEADERS, { error: entry.error });
}

// The lookup and entitlement endpoints answer an error as `error`, while the
// authorization server's own failure is `{"rc": ...}`. Both are read here so a
// caller never has to know which one they hit.
function messageOf(body: unknown): string | undefined {
    if (typeof body !== 'object' || body === null) {
        return undefined;
    }
    const b = body as Record<string, unknown>;
    if (typeof b.error === 'string') {
        return b.error;
    }
    if (typeof b.rc === 'string') {
        return b.rc;
    }
    return undefined;
}

function parseRetryAfter(value: string | null): number | undefined {
    if (value === null) {
        return undefined;
    }
    const text = value.trim();
    // Digits alone, as RFC 9110's delay-seconds is: `Number` would also read `+1`,
    // `0x10`, `1e3` and `1.5` as counts.
    if (/^\d+$/.test(text)) {
        const seconds = Number(text);
        return Number.isFinite(seconds) ? seconds : undefined;
    }
    const when = httpDate(text);
    if (when === undefined) {
        return undefined;
    }
    return Math.max(0, Math.ceil((when - Date.now()) / 1000));
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const MONTH = MONTHS.join('|');
const DAY = 'Mon|Tue|Wed|Thu|Fri|Sat|Sun';
const WEEKDAY = 'Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday';
const TIME = '(\\d{2}):(\\d{2}):(\\d{2})';
const IMF_FIXDATE = new RegExp(`^(?:${DAY}), (\\d{2}) (${MONTH}) (\\d{4}) ${TIME} GMT$`);
const RFC850_DATE = new RegExp(`^(?:${WEEKDAY}), (\\d{2})-(${MONTH})-(\\d{2}) ${TIME} GMT$`);
const ASCTIME_DATE = new RegExp(`^(?:${DAY}) (${MONTH}) ( \\d|\\d{2}) ${TIME} (\\d{4})$`);

/**
 * An HTTP date in milliseconds, in exactly the three forms RFC 9110 has a
 * recipient read, all GMT. `Date.parse` takes far more: ISO 8601 and words such
 * as `Jan 1 2099`, a zone such as `PST` or `+0500`, a day the month lacks
 * (`31 Nov`, rolled into December), and an asctime date as LOCAL time, so a
 * throttle five seconds out would wait none in a browser east of GMT.
 */
function httpDate(text: string): number | undefined {
    let parts: [string, string, number, string, string, string] | undefined;
    let m = IMF_FIXDATE.exec(text);
    if (m !== null) {
        parts = [m[1]!, m[2]!, Number(m[3]), m[4]!, m[5]!, m[6]!];
    } else if ((m = RFC850_DATE.exec(text)) !== null) {
        // A two-digit year more than 50 years ahead is the last such year past.
        let year = 2000 + Number(m[3]);
        if (year > new Date().getUTCFullYear() + 50) {
            year -= 100;
        }
        parts = [m[1]!, m[2]!, year, m[4]!, m[5]!, m[6]!];
    } else if ((m = ASCTIME_DATE.exec(text)) !== null) {
        parts = [m[2]!.trim(), m[1]!, Number(m[6]), m[3]!, m[4]!, m[5]!];
    }
    if (parts === undefined) {
        return undefined;
    }
    const [day, month, year, hour, minute, second] = parts;
    const d = Number(day);
    const mo = MONTHS.indexOf(month);
    const h = Number(hour);
    const mi = Number(minute);
    const s = Number(second);
    const date = new Date(Date.UTC(year, mo, d));
    if (date.getUTCDate() !== d || date.getUTCMonth() !== mo || h > 23 || mi > 59 || s > 60) {
        return undefined;
    }
    return Date.UTC(year, mo, d, h, mi, s);
}
