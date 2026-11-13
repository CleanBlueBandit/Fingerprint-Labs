// Request metadata that Vercel's edge adds to every request, beyond the TLS digests
// (those are in tls-fingerprint.js). Documented at
// https://vercel.com/docs/headers/request-headers
//
//   x-vercel-ip-country, -country-region, -continent, -city, -latitude, -longitude,
//   -timezone, -postal-code   location of the client's public IP address
//   x-vercel-id               regions the request went through, plus a request id
//
// Everything here describes the IP address and the network path, not the device, so it
// is context for consistency checks and not part of any device hash. Every value is
// validated and bounded before it is returned, because off Vercel any client can send
// these headers. Values are marked trusted only when running on Vercel.

import { isOnVercel } from './tls-fingerprint.js';

export const VERCEL_REQUEST_HEADERS = new Set([
    'x-vercel-id',
    'x-vercel-ip-continent',
    'x-vercel-ip-country',
    'x-vercel-ip-country-region',
    'x-vercel-ip-city',
    'x-vercel-ip-latitude',
    'x-vercel-ip-longitude',
    'x-vercel-ip-timezone',
    'x-vercel-ip-postal-code'
]);

const CONTINENTS = new Set(['AF', 'AN', 'AS', 'EU', 'NA', 'OC', 'SA']);

function headerValue(headers, name) {
    const raw = headers?.[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    return typeof value === 'string' ? value.trim() : '';
}

const upperMatch = (value, pattern) => (pattern.test(value) ? value.toUpperCase() : null);

function decodeCity(value) {
    if (!value || value.length > 300) return null;
    try {
        const city = decodeURIComponent(value);
        return city.length <= 100 ? city : null;
    } catch {
        return null; // malformed percent-encoding
    }
}

function coordinate(value, limit) {
    if (!/^-?\d{1,3}(\.\d{1,8})?$/.test(value)) return null;
    const n = Number(value);
    return Math.abs(n) <= limit ? n : null;
}

// IANA names look like Europe/Tbilisi or America/Argentina/Buenos_Aires (or UTC)
function timezone(value) {
    return value.length <= 64 && /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z][A-Za-z0-9_+-]*){0,2}$/.test(value)
        ? value
        : null;
}

// x-vercel-id looks like "cle1::d7jxv-1704551507000-4d96ae5b07e7" or, when a function in
// another region served the request, "sfo1::iad1::abc12-1704551507000-..." (format
// inferred from observed values; Vercel only documents it as the regions hit plus the
// execution region). The last part is the request id, the ones before it are regions.
export function parseVercelId(value) {
    if (!value || value.length > 200) return null;

    const parts = value.split('::');
    const id = parts.pop();
    const regions = parts;
    if (!id || !regions.length || !regions.every((r) => /^[a-z0-9]{2,8}$/.test(r))) return null;

    return {
        id,
        regions,
        edgeRegion: regions[0],
        executionRegion: regions[regions.length - 1]
    };
}

export function readVercelRequest(headers, { onVercel = isOnVercel() } = {}) {
    const geo = {
        country: upperMatch(headerValue(headers, 'x-vercel-ip-country'), /^[a-z]{2}$/i),
        continent: (() => {
            const c = headerValue(headers, 'x-vercel-ip-continent').toUpperCase();
            return CONTINENTS.has(c) ? c : null;
        })(),
        region: upperMatch(headerValue(headers, 'x-vercel-ip-country-region'), /^[a-z0-9]{1,3}$/i),
        city: decodeCity(headerValue(headers, 'x-vercel-ip-city')),
        latitude: coordinate(headerValue(headers, 'x-vercel-ip-latitude'), 90),
        longitude: coordinate(headerValue(headers, 'x-vercel-ip-longitude'), 180),
        timezone: timezone(headerValue(headers, 'x-vercel-ip-timezone')),
        postalCode: (() => {
            const p = headerValue(headers, 'x-vercel-ip-postal-code');
            return /^[A-Za-z0-9 -]{1,12}$/.test(p) ? p : null;
        })()
    };

    const edge = parseVercelId(headerValue(headers, 'x-vercel-id'));

    const hasGeo = Object.values(geo).some((v) => v !== null);
    if (!hasGeo && !edge) {
        return { source: null, trusted: null, geo: null, edge: null };
    }

    return {
        source: 'vercel',
        trusted: onVercel,
        geo: hasGeo ? geo : null,
        edge
    };
}
