// Keeps credentials out of what /fingerprint/info returns and what gets saved.
//
// Vercel adds short-lived bearer credentials to every request it forwards, for example
// x-vercel-oidc-token (a signed JWT for the project) and x-vercel-proxy-signature, and puts a
// signature into the Forwarded header (sig=...). They are useful to the platform, not to a
// fingerprint, and anyone who reads a saved result could replay them while they are valid.

const SENSITIVE_HEADER_NAMES = new Set([
    'authorization',
    'proxy-authorization',
    'x-api-key',
    'x-auth-token'
]);

// Anything that looks like a credential, so a header added by a new platform feature is
// hidden by default instead of leaked until someone notices
const SENSITIVE_HEADER_PATTERN = /(token|secret|password|signature|credential)/i;

export const REDACTED = '[redacted]';

export function isSensitiveHeader(name) {
    const lower = String(name).toLowerCase();
    return SENSITIVE_HEADER_NAMES.has(lower) || SENSITIVE_HEADER_PATTERN.test(lower);
}

// Returns the value to show for a header: redacted, partly redacted, or unchanged
export function redactHeaderValue(name, value) {
    const lower = String(name).toLowerCase();
    if (isSensitiveHeader(lower)) return REDACTED;
    if (lower === 'forwarded' && typeof value === 'string') {
        return value.replace(/(^|[;,\s])sig=[^;,\s]*/gi, `$1sig=${REDACTED}`);
    }
    return value;
}

const redactMap = (map) => {
    if (!map || typeof map !== 'object' || Array.isArray(map)) return;
    for (const name of Object.keys(map)) map[name] = redactHeaderValue(name, map[name]);
};

// Scrubs a fingerprint result (in place) before it is stored, in case it was produced by an
// older version of the endpoint or sent by a modified client
export function scrubFingerprintSecrets(data) {
    const view = data && typeof data === 'object' ? data.serverView : null;
    if (!view || typeof view !== 'object') return data;

    redactMap(view.headers);
    if (view.groups && typeof view.groups === 'object') {
        for (const group of Object.values(view.groups)) redactMap(group);
    }
    return data;
}
