// Tests for the parts of the fingerprint scripts that run without a browser.
// Not covered here: WebGL, real audio rendering, fonts, MediaCapabilities, screen and device
// APIs. Those need a real browser; see the stub tests below for status handling only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { loadFingerprint } from './load-fingerprint.mjs';

const ALL = ['fingerprint-lib.js', 'fingerprint-wasm.js', 'fingerprint-media.js', 'fingerprint-text.js', 'fingerprint-env.js'];
const fp = loadFingerprint(ALL);
const run = (id, ctx = {}) => {
    const t = fp.get('FP_TEST_REGISTRY').find((x) => x.id === id);
    return fp.get('runRegisteredTest')(t, { result: {}, opts: {}, ...ctx });
};

test('pure-JS SHA-256 matches crypto for many lengths', () => {
    const sha = fp.get('sha256Fallback');
    for (const len of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 1000, 100000]) {
        const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 31 + 7) & 255);
        assert.equal(sha(bytes), createHash('sha256').update(bytes).digest('hex'), `length ${len}`);
    }
});

test('hashBytes accepts Float32Array views and is SHA-256', async () => {
    const f = new Float32Array([1.5, -0, NaN, 1e-30]);
    const h = await fp.get('hashBytes')(f);
    assert.equal(h.algorithm, 'SHA-256');
    assert.equal(h.value, createHash('sha256').update(Buffer.from(f.buffer)).digest('hex'));
});

test('hashing works without crypto.subtle (insecure context)', async () => {
    const insecure = loadFingerprint(['fingerprint-lib.js'], { crypto: {} });
    const h = await insecure.get('hashString')('abc');
    assert.equal(h.algorithm, 'SHA-256');
    assert.equal(h.value, createHash('sha256').update('abc').digest('hex'));
});

test('stableStringify: key order, -0, NaN, BigInt, typed arrays', () => {
    const s = fp.get('stableStringify');
    assert.equal(s({ b: 1, a: 2 }), s({ a: 2, b: 1 }));
    assert.notEqual(s(-0), s(0));
    assert.notEqual(s(NaN), s(null));
    assert.notEqual(s(1n), s(1));
    assert.notEqual(s('NaN'), s(NaN));
    assert.equal(s({ a: undefined, b: 1 }), s({ b: 1 }));
    assert.notEqual(s(new Float32Array([1])), s(new Float64Array([1])));
});

test('harness: the four statuses are distinguished', async () => {
    const H = fp.get('runRegisteredTest');
    const mk = (run) => ({ id: 't', category: 'static', run });
    const ctx = { result: {}, opts: {} };
    const un = fp.get('unsupported'), av = fp.get('unavailable');
    assert.equal((await H(mk(async () => un('x')), ctx)).status, 'unsupported');
    assert.equal((await H(mk(async () => av('x')), ctx)).status, 'unavailable');
    assert.equal((await H(mk(async () => { throw new Error('boom'); }), ctx)).status, 'failed');
    const blocked = await H(mk(async () => { throw Object.assign(new Error('no'), { name: 'SecurityError' }); }), ctx);
    assert.equal(blocked.status, 'unavailable');
    const ok = await H(mk(async () => ({ raw: { a: 1 }, normalized: { a: 1 } })), ctx);
    assert.equal(ok.status, 'success');
    assert.match(ok.hash, /^[0-9a-f]{64}$/);
    const slow = await H({ ...mk(() => new Promise(() => {})), timeoutMs: 20 }, ctx);
    assert.equal(slow.status, 'failed');
    assert.equal(slow.reason, 'timeout');
    const optIn = await H({ ...mk(async () => ({})), optIn: 'screenDetails' }, ctx);
    assert.equal(optIn.status, 'unavailable');
});

test('registered tests cover every requested area', () => {
    const ids = fp.get('FP_TEST_REGISTRY').map((t) => t.id).sort();
    for (const id of ['audioCapabilities', 'audioRendering', 'webglRendering', 'fontAnalysis', 'hardwareEnvironment', 'browserSettings',
        'storageEnvironment', 'screenDetails', 'wasmCapabilities', 'wasmComputation', 'apiAvailability', 'deviceAvailability',
        'mediaCapabilities', 'indexedDbBehavior', 'cacheApiBehavior', 'compressionBehavior', 'regexpBehavior', 'intlData',
        'localeSettings', 'timezoneBehavior']) assert.ok(ids.includes(id), id);
    assert.equal(new Set(ids).size, ids.length, 'ids are unique');
    for (const t of fp.get('FP_TEST_REGISTRY')) assert.ok(['static', 'configuration', 'behavioral'].includes(t.category), t.id);
});

test('WebAssembly: every program matches its JavaScript reference', async () => {
    const r = await run('wasmComputation');
    assert.equal(r.status, 'success', r.error || r.reason);
    for (const g of ['integer', 'float', 'simd']) {
        for (const [name, v] of Object.entries(r.raw[g])) {
            assert.equal(v.status, 'success', `${g}.${name}`);
            if ('matchesReference' in v) assert.equal(v.matchesReference, true, `${g}.${name}`);
        }
    }
});

test('WebAssembly: results are deterministic across runs', async () => {
    const a = await run('wasmComputation'), b = await run('wasmComputation');
    assert.equal(a.hash, b.hash);
    assert.equal(a.hashes.implementationDefined, b.hashes.implementationDefined);
});

test('WebAssembly: capability test reports thread execution as unsupported without Worker', async () => {
    const r = await run('wasmCapabilities');
    assert.equal(r.status, 'success');
    assert.equal(r.raw.features.simd, true);
    assert.equal(r.raw.threads.execution.status, 'unsupported');
});

test('WebAssembly: missing WebAssembly is unsupported, not failed', async () => {
    const bare = loadFingerprint(['fingerprint-lib.js', 'fingerprint-wasm.js'], {});
    bare.context.WebAssembly = undefined;
    const t = bare.get('FP_TEST_REGISTRY').find((x) => x.id === 'wasmCapabilities');
    const r = await bare.get('runRegisteredTest')(t, { result: {}, opts: {} });
    assert.equal(r.status, 'unsupported');
});

test('RegExp, Intl, timezone and compression tests run and are repeatable', async () => {
    for (const id of ['regexpBehavior', 'intlData', 'localeSettings', 'timezoneBehavior', 'compressionBehavior', 'hardwareEnvironment', 'browserSettings']) {
        const a = await run(id), b = await run(id);
        assert.notEqual(a.status, 'failed', `${id}: ${a.error}`);
        assert.equal(a.hash, b.hash, id);
    }
});

test('compression: gzip round trips and output is hashed', async () => {
    const withStreams = loadFingerprint(ALL, { CompressionStream, DecompressionStream, Response, Blob });
    const t = withStreams.get('FP_TEST_REGISTRY').find((x) => x.id === 'compressionBehavior');
    const r = await withStreams.get('runRegisteredTest')(t, { result: {}, opts: {} });
    assert.equal(r.status, 'success');
    assert.equal(r.raw.formats.gzip.roundTrips, true);
    assert.match(r.raw.formats.gzip.outputSha256, /^[0-9a-f]{64}$/);
});

test('timezone: Intl and Date agree in this environment', async () => {
    const r = await run('timezoneBehavior');
    assert.equal(r.normalized.intlAgreesWithDate, true);
});

test('audio rendering with a fake engine: noise is detected and excluded', async () => {
    let call = 0;
    class FakeOAC {
        constructor(ch, length, rate) { this.length = length; }
        createOscillator() { return { frequency: { value: 0, setValueAtTime() {}, exponentialRampToValueAtTime() {}, linearRampToValueAtTime() {} }, connect() {}, start() {} }; }
        createDynamicsCompressor() { const p = () => ({ value: 0 }); return { threshold: p(), knee: p(), ratio: p(), attack: p(), release: p(), connect() {} }; }
        createBiquadFilter() { return { frequency: { value: 0 }, Q: { value: 0 }, connect() {} }; }
        get destination() { return {}; }
        async startRendering() {
            call++;
            const noisy = this.noisy;
            const data = Float32Array.from({ length: this.length }, (_, i) => Math.sin(i / 7) * 0.5 + (noisy ? call * 1e-3 : 0));
            return { getChannelData: () => data };
        }
    }
    const stable = loadFingerprint(['fingerprint-lib.js', 'fingerprint-media.js'], { OfflineAudioContext: FakeOAC });
    const t = stable.get('FP_TEST_REGISTRY').find((x) => x.id === 'audioRendering');
    const ok = await stable.get('runRegisteredTest')(t, { result: {}, opts: {} });
    assert.equal(ok.status, 'success');
    const v = ok.normalized.variants.triangleCompressor;
    assert.equal(v.deterministic, true);
    assert.match(v.quantizedSha256, /^[0-9a-f]{64}$/);
    assert.match(ok.hashes.rawSamples, /^[0-9a-f]{64}$/);

    FakeOAC.prototype.noisy = true;
    const noisy = loadFingerprint(['fingerprint-lib.js', 'fingerprint-media.js'], { OfflineAudioContext: FakeOAC });
    const n = await noisy.get('runRegisteredTest')(noisy.get('FP_TEST_REGISTRY').find((x) => x.id === 'audioRendering'), { result: {}, opts: {} });
    assert.equal(n.normalized.variants.triangleCompressor.deterministic, false);
    assert.equal(n.normalized.variants.triangleCompressor.quantizedSha256, null);
});

test('audio capabilities without Web Audio is unsupported', async () => {
    const r = await run('audioCapabilities');
    assert.equal(r.status, 'unsupported');
});

test('characteristics: categories hash separately; failed tests are excluded', async () => {
    const mkTest = (id, category, status, hash) => ({ id, category, status, reason: status === 'success' ? null : 'x', groups: ['gpu'], hash });
    const result = {
        tests: {
            a: mkTest('a', 'static', 'success', 'h1'),
            b: mkTest('b', 'behavioral', 'failed', null),
            c: mkTest('c', 'configuration', 'unsupported', null)
        }
    };
    const c1 = await fp.get('buildCharacteristics')(result);
    result.tests.b = mkTest('b', 'behavioral', 'unavailable', null);
    const c2 = await fp.get('buildCharacteristics')(result);
    assert.equal(c1.behavioral.hash, c2.behavioral.hash, 'transient failures never move a hash');
    assert.ok(c1.behavioral.excluded.some((e) => e.id === 'b'));
    result.tests.a = mkTest('a', 'static', 'success', 'h2');
    const c3 = await fp.get('buildCharacteristics')(result);
    assert.notEqual(c1.static.hash, c3.static.hash);
    assert.equal(c1.configuration.hash, c3.configuration.hash, 'categories are independent');
    assert.ok(c1.correlationGroups.gpu.members.includes('test:a'));
});

test('webgl rendering against a stub context: statuses and cleanup', async () => {
    // Minimal fake that records deletes, to check resources are released
    const calls = { deletes: 0, lose: 0 };
    const px = (w, h) => Uint8Array.from({ length: w * h * 4 }, (_, i) => (i * 7) & 255);
    const gl = new Proxy({}, {
        get(_, name) {
            if (name === 'checkFramebufferStatus') return () => 0x8CD5;
            if (name === 'FRAMEBUFFER_COMPLETE') return 0x8CD5;
            if (name === 'getShaderParameter' || name === 'getProgramParameter') return () => true;
            if (name === 'getShaderPrecisionFormat') return () => ({ precision: 23 });
            if (name === 'getError') return () => 0;
            if (name === 'NO_ERROR') return 0;
            if (name === 'readPixels') return (x, y, w, h, f, t, out) => out.set(px(w, h));
            if (name === 'getExtension') return (n) => (n === 'WEBGL_lose_context' ? { loseContext() { calls.lose++; } } : null);
            if (/^delete/.test(String(name))) return () => { calls.deletes++; };
            if (/^[A-Z0-9_]+$/.test(String(name))) return 1;
            return () => ({});
        }
    });
    const doc = { createElement: () => ({ width: 0, height: 0, getContext: () => gl }) };
    const env = loadFingerprint(['fingerprint-lib.js', 'fingerprint-media.js'], {
        document: doc, WebGLRenderingContext: function () {}, WebGL2RenderingContext: function () {}
    });
    const t = env.get('FP_TEST_REGISTRY').find((x) => x.id === 'webglRendering');
    const r = await env.get('runRegisteredTest')(t, { result: {}, opts: {} });
    assert.equal(r.status, 'success', r.error || r.reason);
    assert.equal(r.raw.webgl.status, 'success');
    assert.ok(Object.keys(r.raw.webgl.tiles).length === 8);
    assert.ok(calls.deletes > 0, 'resources deleted');
    assert.equal(calls.lose, 2, 'both contexts released');
    assert.equal(r.raw.webgl.deterministic, true);
});

test('webgl rendering: no context is unavailable, no interface is unsupported', async () => {
    const doc = { createElement: () => ({ width: 0, height: 0, getContext: () => null }) };
    const blocked = loadFingerprint(['fingerprint-lib.js', 'fingerprint-media.js'], { document: doc, WebGLRenderingContext() {}, WebGL2RenderingContext() {} });
    const r1 = await blocked.get('runRegisteredTest')(blocked.get('FP_TEST_REGISTRY').find((x) => x.id === 'webglRendering'), { result: {}, opts: {} });
    assert.equal(r1.status, 'unavailable');
    const none = loadFingerprint(['fingerprint-lib.js', 'fingerprint-media.js'], { document: doc });
    const r2 = await none.get('runRegisteredTest')(none.get('FP_TEST_REGISTRY').find((x) => x.id === 'webglRendering'), { result: {}, opts: {} });
    assert.equal(r2.status, 'unsupported');
});
