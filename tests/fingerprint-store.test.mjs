import test from 'node:test';
import assert from 'node:assert/strict';
import { extractHashes, sanitizeData, isPlainObject, toSummary } from '../lib/fingerprint-store.js';

test('extractHashes reads the indexed columns, including { algorithm, value } hashes', () => {
    const h = extractHashes({
        combinedHash: { algorithm: 'SHA-256', value: 'a'.repeat(64) },
        characteristics: {
            schema: 1,
            static: { hash: 'b'.repeat(64) },
            configuration: { hash: 'c'.repeat(64) },
            behavioral: { hash: 'd'.repeat(64) }
        }
    });
    assert.deepEqual(h, {
        combinedHash: 'a'.repeat(64),
        staticHash: 'b'.repeat(64),
        configurationHash: 'c'.repeat(64),
        behavioralHash: 'd'.repeat(64),
        schemaVersion: 1
    });
});

test('extractHashes tolerates missing, oversized and non-string hashes', () => {
    assert.deepEqual(extractHashes({}), {
        combinedHash: null, staticHash: null, configurationHash: null, behavioralHash: null, schemaVersion: null
    });
    const h = extractHashes({ combinedHash: 'x'.repeat(65), characteristics: { schema: '1', static: { hash: 42 } } });
    assert.equal(h.combinedHash, null);
    assert.equal(h.staticHash, null);
    assert.equal(h.schemaVersion, null);
});

test('sanitizeData strips NUL characters that JSONB rejects', () => {
    const out = sanitizeData({ a: 'x\u0000y', nested: ['\u0000'], keep: 1, drop: undefined });
    assert.deepEqual(out, { a: 'xy', nested: [''], keep: 1 });
});

test('isPlainObject', () => {
    assert.equal(isPlainObject({}), true);
    assert.equal(isPlainObject([]), false);
    assert.equal(isPlainObject(null), false);
    assert.equal(isPlainObject('x'), false);
});

test('toSummary leaves the payload out', () => {
    const s = toSummary({ id: 1, createdAt: 'now', combinedHash: 'a', staticHash: null, configurationHash: null, behavioralHash: null, schemaVersion: 1, data: { big: true }, userId: 9 });
    assert.equal('data' in s, false);
    assert.equal('userId' in s, false);
});
