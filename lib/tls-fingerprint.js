// TLS fingerprints (JA3 / JA4) as reported by Vercel.
//
// Node never sees the ClientHello when TLS ends at Vercel's edge, so the edge computes
// the fingerprints and sends them to the deployment as request headers (available on
// all plans, see https://vercel.com/docs/vercel-firewall/firewall-concepts):
//
//   x-vercel-ja4-digest   JA4 fingerprint (preferred)
//   x-vercel-ja3-digest   JA3 fingerprint
//
// This module only validates and decodes those values. It does not compute anything.
//
// Caveats, from Vercel's own guidance and community reports:
//   - A fingerprint identifies a TLS client configuration, not a person. Everyone on the
//     same browser build shares one (Chrome stable commonly yields
//     t13d1516h2_8daaf6152771_02713d6af862), so use it as one weak signal among several.
//   - Outside Vercel nothing strips these headers from incoming requests, so a client can
//     send any value it likes. Values are only marked trusted when running on Vercel.

export const VERCEL_JA4_HEADER = 'x-vercel-ja4-digest';
export const VERCEL_JA3_HEADER = 'x-vercel-ja3-digest';
export const TLS_FINGERPRINT_HEADERS = new Set([VERCEL_JA4_HEADER, VERCEL_JA3_HEADER]);

// JA4 (FoxIO): a_b_c
//   a = protocol (t TCP, q QUIC, d DTLS), TLS version, SNI (d domain / i IP or none),
//       cipher count, extension count, first ALPN value's first and last character
//   b = first 12 hex of sha256 of the sorted cipher suites
//   c = first 12 hex of sha256 of the sorted extensions plus signature algorithms
const JA4_PATTERN = /^([tqd])([a-z0-9]{2})([di])(\d{2})(\d{2})([a-z0-9]{2})_([0-9a-f]{12})_([0-9a-f]{12})$/;
const JA3_PATTERN = /^[0-9a-f]{32}$/;

const TLS_VERSIONS = {
    '13': 'TLS 1.3', '12': 'TLS 1.2', '11': 'TLS 1.1', '10': 'TLS 1.0',
    's3': 'SSL 3.0', 's2': 'SSL 2.0', 'd1': 'DTLS 1.0', 'd2': 'DTLS 1.2', 'd3': 'DTLS 1.3'
};
const PROTOCOLS = { t: 'tcp', q: 'quic', d: 'dtls' };

// Header values can arrive as an array if a header is repeated; use the first
function headerValue(headers, name) {
    const raw = headers?.[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    return typeof value === 'string' ? value.trim() : '';
}

// Splits a JA4 string into its named parts. Returns null if it is not well-formed.
export function parseJa4(value) {
    const m = JA4_PATTERN.exec(value ?? '');
    if (!m) return null;

    const [, protocol, version, sni, cipherCount, extensionCount, alpn, cipherHash, extensionHash] = m;
    return {
        protocol: PROTOCOLS[protocol],
        tlsVersion: TLS_VERSIONS[version] ?? version,
        sni: sni === 'd' ? 'domain' : 'ip-or-none',
        cipherCount: Number(cipherCount),
        extensionCount: Number(extensionCount),
        alpn: alpn === '00' ? null : alpn, // 'h2', 'h1', ...
        cipherHash,
        extensionHash
    };
}

export function isOnVercel(env = process.env) {
    return env.VERCEL === '1';
}

// Reads the fingerprints out of a request's (lowercased) headers, the shape Express gives.
// source: 'vercel' when at least one valid digest is present, otherwise null.
// trusted: true only on Vercel, where the edge sets the headers; false anywhere else.
export function readTlsFingerprint(headers, { onVercel = isOnVercel() } = {}) {
    const ja4Raw = headerValue(headers, VERCEL_JA4_HEADER);
    const ja3Raw = headerValue(headers, VERCEL_JA3_HEADER);

    const ja4 = ja4Raw.toLowerCase();
    const ja3 = ja3Raw.toLowerCase();
    const ja4Valid = JA4_PATTERN.test(ja4);
    const ja3Valid = JA3_PATTERN.test(ja3);

    if (!ja4Valid && !ja3Valid) {
        return { source: null, trusted: null, ja4: null, ja3: null, ja4Parts: null };
    }

    return {
        source: 'vercel',
        trusted: onVercel,
        ja4: ja4Valid ? ja4 : null,
        ja3: ja3Valid ? ja3 : null,
        ja4Parts: ja4Valid ? parseJa4(ja4) : null
    };
}

// Explains an empty or untrusted result, for the response's tlsNote
export function tlsNoteFor(fingerprint, { onVercel = isOnVercel() } = {}) {
    if (fingerprint.source === 'vercel' && !fingerprint.trusted) {
        return 'These values came from request headers, but this server is not running on Vercel, '
            + 'so nothing guarantees they were set by Vercel. Any client can send these headers.';
    }

    if (fingerprint.source === null) {
        return onVercel
            ? 'Vercel did not send a valid TLS fingerprint header with this request.'
            : `Not running on Vercel, so there is no ${VERCEL_JA4_HEADER} or ${VERCEL_JA3_HEADER} header. `
                + 'Deploy to Vercel to get TLS fingerprints; they cannot be computed from inside Node.';
    }

    return null;
}
