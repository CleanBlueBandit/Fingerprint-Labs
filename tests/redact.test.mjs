import test from 'node:test';
import assert from 'node:assert/strict';
import { isSensitiveHeader, redactHeaderValue, scrubFingerprintSecrets, REDACTED } from '../lib/redact.js';
import { sanitizeData } from '../lib/fingerprint-store.js';

test('credential headers are sensitive, ordinary ones are not', () => {
    for (const name of ['authorization', 'x-vercel-oidc-token', 'x-vercel-proxy-signature',
        'x-vercel-proxy-signature-ts', 'X-Api-Key', 'x-csrf-token', 'x-client-secret']) {
        assert.equal(isSensitiveHeader(name), true, name);
    }
    for (const name of ['user-agent', 'x-vercel-ja4-digest', 'x-vercel-id', 'x-vercel-ip-city',
        'x-forwarded-for', 'sec-ch-ua', 'accept-language']) {
        assert.equal(isSensitiveHeader(name), false, name);
    }
});

test('the signature inside Forwarded is hidden but the rest is kept', () => {
    const forwarded = 'for=179.61.254.36;host=example.vercel.app;proto=https;sig=0QmVhcmVy;exp=1794572882';
    assert.equal(
        redactHeaderValue('forwarded', forwarded),
        `for=179.61.254.36;host=example.vercel.app;proto=https;sig=${REDACTED};exp=1794572882`
    );
    assert.equal(redactHeaderValue('forwarded', 'for=1.2.3.4'), 'for=1.2.3.4');
});

test('ordinary values pass through unchanged', () => {
    assert.equal(redactHeaderValue('user-agent', 'Mozilla/5.0'), 'Mozilla/5.0');
});

const leaky = () => ({
    serverView: {
        headers: { 'x-vercel-oidc-token': 'eyJ.a.b', 'user-agent': 'x', forwarded: 'for=1.1.1.1;sig=abc;exp=1' },
        groups: { proxy: { forwarded: 'for=1.1.1.1;sig=abc;exp=1' }, vercel: { 'x-vercel-id': 'fra1::abc' } }
    }
});

test('saved results are scrubbed, including groups', () => {
    const out = scrubFingerprintSecrets(leaky());
    assert.equal(out.serverView.headers['x-vercel-oidc-token'], REDACTED);
    assert.equal(out.serverView.headers['user-agent'], 'x');
    assert.equal(out.serverView.headers.forwarded, `for=1.1.1.1;sig=${REDACTED};exp=1`);
    assert.equal(out.serverView.groups.proxy.forwarded, `for=1.1.1.1;sig=${REDACTED};exp=1`);
    assert.equal(out.serverView.groups.vercel['x-vercel-id'], 'fra1::abc');
});

test('sanitizeData applies the scrub and tolerates results without a server view', () => {
    assert.equal(sanitizeData(leaky()).serverView.headers['x-vercel-oidc-token'], REDACTED);
    assert.deepEqual(sanitizeData({ a: 1 }), { a: 1 });
    assert.equal(scrubFingerprintSecrets(null), null);
    assert.deepEqual(scrubFingerprintSecrets({ serverView: { headers: 'weird' } }), { serverView: { headers: 'weird' } });
});
