import test from 'node:test';
import assert from 'node:assert/strict';
import { readVercelRequest, parseVercelId, VERCEL_REQUEST_HEADERS } from '../lib/vercel-request.js';
import { loadFingerprint } from './load-fingerprint.mjs';

const HEADERS = {
    'x-vercel-id': 'sfo1::iad1::d7jxv-1704551507000-4d96ae5b07e7',
    'x-vercel-ip-continent': 'NA',
    'x-vercel-ip-country': 'US',
    'x-vercel-ip-country-region': 'TX',
    'x-vercel-ip-city': 'San%20Antonio',
    'x-vercel-ip-latitude': '29.4227',
    'x-vercel-ip-longitude': '-98.4927',
    'x-vercel-ip-timezone': 'America/Chicago',
    'x-vercel-ip-postal-code': '78205',
    'x-vercel-ip-as-number': '215348'
};

test('reads and decodes the full set of Vercel headers', () => {
    const r = readVercelRequest(HEADERS, { onVercel: true });
    assert.equal(r.source, 'vercel');
    assert.equal(r.trusted, true);
    assert.deepEqual(r.geo, {
        country: 'US', continent: 'NA', region: 'TX', city: 'San Antonio',
        latitude: 29.4227, longitude: -98.4927, timezone: 'America/Chicago', postalCode: '78205', asn: 215348
    });
    assert.deepEqual(r.edge, {
        id: 'd7jxv-1704551507000-4d96ae5b07e7',
        regions: ['sfo1', 'iad1'], edgeRegion: 'sfo1', executionRegion: 'iad1'
    });
});

test('non-ASCII cities are decoded', () => {
    const r = readVercelRequest({ 'x-vercel-ip-city': 'T%E2%80%99bilisi' }, { onVercel: true });
    assert.equal(r.geo.city, 'T’bilisi');
});

test('off Vercel the values are reported but untrusted', () => {
    assert.equal(readVercelRequest(HEADERS, { onVercel: false }).trusted, false);
});

test('single-region x-vercel-id', () => {
    assert.deepEqual(parseVercelId('cle1::d7jxv-1704551507000-4d96ae5b07e7'), {
        id: 'd7jxv-1704551507000-4d96ae5b07e7', regions: ['cle1'], edgeRegion: 'cle1', executionRegion: 'cle1'
    });
});

test('malformed values are dropped individually', () => {
    const r = readVercelRequest({
        'x-vercel-ip-country': 'USA',
        'x-vercel-ip-continent': 'XX',
        'x-vercel-ip-city': '%E0%A4%A',
        'x-vercel-ip-latitude': '123.4',
        'x-vercel-ip-longitude': 'abc',
        'x-vercel-ip-timezone': '../etc/passwd',
        'x-vercel-ip-postal-code': '<script>',
        'x-vercel-ip-as-number': 'AS123',
        'x-vercel-ip-country-region': 'CA',
        'x-vercel-id': 'no-separator'
    }, { onVercel: true });
    assert.deepEqual(r.geo, {
        country: null, continent: null, region: 'CA', city: null,
        latitude: null, longitude: null, timezone: null, postalCode: null, asn: null
    });
    assert.equal(r.edge, null);
});

test('nothing usable gives an empty result', () => {
    assert.deepEqual(readVercelRequest({}), { source: null, trusted: null, geo: null, edge: null });
    assert.deepEqual(readVercelRequest({ 'x-vercel-ip-country': 'zzz', 'x-vercel-id': '' }),
        { source: null, trusted: null, geo: null, edge: null });
});

test('overlong values are rejected', () => {
    const r = readVercelRequest({ 'x-vercel-ip-city': 'a'.repeat(400), 'x-vercel-ip-country': 'us' }, { onVercel: true });
    assert.equal(r.geo.city, null);
    assert.equal(r.geo.country, 'US');
});

test('a missing postal code and ASN stay null while the rest is read', () => {
    const r = readVercelRequest({ 'x-vercel-ip-country': 'GE', 'x-vercel-ip-timezone': 'Asia/Tbilisi' }, { onVercel: true });
    assert.equal(r.geo.postalCode, null);
    assert.equal(r.geo.asn, null);
    assert.equal(r.geo.country, 'GE');
});

test('header set contains exactly the documented headers', () => {
    assert.equal(VERCEL_REQUEST_HEADERS.size, 10);
    assert.ok(VERCEL_REQUEST_HEADERS.has('x-vercel-ip-as-number'));
    assert.ok(VERCEL_REQUEST_HEADERS.has('x-vercel-ip-postal-code'));
});

// Client side: time zone consistency check
const consistency = (ipTimeZone, browserTimeZone) => {
    const fp = loadFingerprint(['fingerprint-lib.js'], {
        navigator: { languages: ['en-US'], language: 'en-US', userAgent: 'x' }
    });
    fp.context.Intl = Intl;
    const RealDTF = Intl.DateTimeFormat;
    // The sandbox shares this process's Intl; pin the browser zone by wrapping resolvedOptions
    const original = RealDTF.prototype.resolvedOptions;
    RealDTF.prototype.resolvedOptions = function () { return { ...original.call(this), timeZone: browserTimeZone }; };
    try {
        return fp.get('getConsistency')({
            serverView: {
                headers: {}, ip: null,
                vercel: ipTimeZone ? { geo: { timezone: ipTimeZone } } : null
            }
        });
    } finally {
        RealDTF.prototype.resolvedOptions = original;
    }
};

test('time zone check compares offsets, so aliases match', () => {
    assert.equal(consistency('Asia/Calcutta', 'Asia/Kolkata').ipTimeZoneMatchesBrowser, true);
    assert.equal(consistency('Asia/Tbilisi', 'Asia/Tbilisi').ipTimeZoneMatchesBrowser, true);
});

test('time zone check flags different offsets', () => {
    assert.equal(consistency('Asia/Tbilisi', 'America/Chicago').ipTimeZoneMatchesBrowser, false);
});

test('time zone check is null without data or with an unknown zone', () => {
    assert.equal(consistency(null, 'Asia/Tbilisi').ipTimeZoneMatchesBrowser, null);
    assert.equal(consistency('Mars/Olympus', 'Asia/Tbilisi').ipTimeZoneMatchesBrowser, null);
});
