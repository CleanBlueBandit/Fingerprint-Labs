import test from 'node:test';
import assert from 'node:assert/strict';
import {
    parseJa4, readTlsFingerprint, tlsNoteFor, TLS_FINGERPRINT_HEADERS
} from '../lib/tls-fingerprint.js';

// Published Chrome JA4, also reported in Vercel community threads
const CHROME_JA4 = 't13d1516h2_8daaf6152771_02713d6af862';
const JA3 = '771d1f2f5b1e3d0b4f4c0a9a2b6c7d8e';

test('parseJa4 decodes the readable part and keeps both hashes', () => {
    assert.deepEqual(parseJa4(CHROME_JA4), {
        protocol: 'tcp',
        tlsVersion: 'TLS 1.3',
        sni: 'domain',
        cipherCount: 15,
        extensionCount: 16,
        alpn: 'h2',
        cipherHash: '8daaf6152771',
        extensionHash: '02713d6af862'
    });
});

test('parseJa4 handles QUIC, no ALPN and no SNI', () => {
    const ok = parseJa4('q13i090000_aaaaaaaaaaaa_bbbbbbbbbbbb');
    assert.equal(ok.protocol, 'quic');
    assert.equal(ok.sni, 'ip-or-none');
    assert.equal(ok.alpn, null);
});

test('parseJa4 rejects garbage', () => {
    for (const bad of ['', 'abc', null, undefined, CHROME_JA4 + 'x', CHROME_JA4.toUpperCase(), 'x13d1516h2_8daaf6152771_02713d6af862']) {
        assert.equal(parseJa4(bad), null);
    }
});

test('readTlsFingerprint reads the Vercel headers and trusts them on Vercel', () => {
    const fp = readTlsFingerprint(
        { 'x-vercel-ja4-digest': CHROME_JA4, 'x-vercel-ja3-digest': JA3 },
        { onVercel: true }
    );
    assert.equal(fp.source, 'vercel');
    assert.equal(fp.trusted, true);
    assert.equal(fp.ja4, CHROME_JA4);
    assert.equal(fp.ja3, JA3);
    assert.equal(fp.ja4Parts.tlsVersion, 'TLS 1.3');
    assert.equal(tlsNoteFor(fp, { onVercel: true }), null);
});

test('off Vercel the same headers are reported but not trusted', () => {
    const fp = readTlsFingerprint({ 'x-vercel-ja4-digest': CHROME_JA4 }, { onVercel: false });
    assert.equal(fp.source, 'vercel');
    assert.equal(fp.trusted, false);
    assert.equal(fp.ja3, null);
    assert.match(tlsNoteFor(fp, { onVercel: false }), /not running on Vercel/);
});

test('missing or malformed headers give an empty result with a note', () => {
    for (const onVercel of [true, false]) {
        for (const headers of [{}, { 'x-vercel-ja4-digest': 'nonsense', 'x-vercel-ja3-digest': 'zz' }]) {
            const fp = readTlsFingerprint(headers, { onVercel });
            assert.deepEqual(fp, { source: null, trusted: null, ja4: null, ja3: null, ja4Parts: null });
            assert.ok(tlsNoteFor(fp, { onVercel }));
        }
    }
});

test('values are normalised: trimmed, lowercased, first of a repeated header', () => {
    const fp = readTlsFingerprint({ 'x-vercel-ja4-digest': [`  ${CHROME_JA4.toUpperCase()} `, 'other'] }, { onVercel: true });
    assert.equal(fp.ja4, CHROME_JA4);
});

test('only the two Vercel headers are treated as TLS fingerprint headers', () => {
    assert.deepEqual([...TLS_FINGERPRINT_HEADERS].sort(), ['x-vercel-ja3-digest', 'x-vercel-ja4-digest']);
});
