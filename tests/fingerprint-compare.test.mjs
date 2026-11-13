import test from 'node:test';
import assert from 'node:assert/strict';
import { compareFingerprints, verdictFor } from '../lib/fingerprint-compare.js';

const base = () => ({
    browser: { userAgent: 'UA/1', platform: 'Win32', languages: ['en-US', 'en'], timezone: 'Asia/Tbilisi' },
    display: { screen: { width: 1920, height: 1080 }, devicePixelRatio: 1 },
    canvas: { hash: 'canvas-1' },
    fonts: { tested: 3, installed: ['Arial', 'Calibri', 'Consolas', 'Segoe UI'] },
    webgl: { vendor: 'V', renderer: 'R', maxTextureSize: 16384 },
    audio: { fingerprint: 'audio-1', output: { sampleRate: 48000, baseLatency: 0.01, state: 'running' } },
    tests: {
        webglRendering: { status: 'success', category: 'behavioral', hash: 'wr-1' },
        intlData: { status: 'success', category: 'static', hash: 'intl-1' }
    }
});

const find = (cmp, id) => cmp.components.find((c) => c.id === id);

test('identical fingerprints score 100 and are "Identical"', () => {
    const c = compareFingerprints(base(), base());
    assert.equal(c.score, 100);
    assert.equal(c.verdict, 'Identical');
});

test('is symmetric', () => {
    const b = base();
    b.canvas.hash = 'canvas-2';
    b.fonts.installed.pop();
    assert.equal(compareFingerprints(base(), b).score, compareFingerprints(b, base()).score);
});

test('a heavy component costs more than a light one', () => {
    const heavy = base();
    heavy.canvas.hash = 'changed'; // weight 8
    const light = base();
    light.display.devicePixelRatio = 2; // weight 2
    assert.ok(compareFingerprints(base(), heavy).score < compareFingerprints(base(), light).score);
});

test('one changed hash removes exactly its share of the weight', () => {
    const b = base();
    b.canvas.hash = 'changed';
    const c = compareFingerprints(base(), b);
    const total = c.components.filter((x) => x.status !== 'skipped').reduce((n, x) => n + x.weight, 0);
    assert.equal(c.score, Math.round(((total - find(c, 'canvas').weight) / total) * 1000) / 10);
    assert.equal(find(c, 'canvas').status, 'different');
});

test('font lists are compared as sets, giving partial credit', () => {
    const b = base();
    b.fonts.installed = ['Arial', 'Calibri', 'Consolas', 'Comic Sans'];
    const f = find(compareFingerprints(base(), b), 'fonts');
    assert.equal(f.status, 'partial');
    assert.equal(f.similarity, 0.6); // 3 shared of 5 in the union
    assert.match(f.changed[0], /\+1 \/ -1/);
});

test('components missing or failed on one side are skipped, not penalised', () => {
    const b = base();
    delete b.canvas;
    b.webgl = { error: 'Error: boom' };
    const c = compareFingerprints(base(), b);
    assert.equal(find(c, 'canvas').status, 'skipped');
    assert.equal(find(c, 'webgl').status, 'skipped');
    assert.equal(c.score, 100);
    assert.ok(c.coverage < 1);
});

test('volatile audio output fields are ignored', () => {
    const b = base();
    b.audio.output.baseLatency = 0.5;
    b.audio.output.state = 'suspended';
    assert.equal(find(compareFingerprints(base(), b), 'audioOutput').status, 'same');
});

test('tests: failed ones are skipped, unsupported vs success differs', () => {
    const b = base();
    b.tests.intlData = { status: 'failed', category: 'static' };
    b.tests.webglRendering = { status: 'unsupported', category: 'behavioral' };
    const c = compareFingerprints(base(), b);
    assert.equal(find(c, 'test:intlData').status, 'skipped');
    assert.equal(find(c, 'webglRendering').status, 'different');
});

test('no overlap gives a null score', () => {
    const c = compareFingerprints({}, {});
    assert.equal(c.score, null);
    assert.equal(c.verdict, null);
});

test('group scores are reported', () => {
    const b = base();
    b.canvas.hash = 'changed';
    const c = compareFingerprints(base(), b);
    assert.ok(c.groups.rendering.score < 100);
    assert.equal(c.groups.browser.score, 100);
});

test('verdict thresholds', () => {
    assert.equal(verdictFor(100), 'Identical');
    assert.equal(verdictFor(95), 'Very similar');
    assert.equal(verdictFor(75), 'Similar');
    assert.equal(verdictFor(50), 'Partly similar');
    assert.equal(verdictFor(10), 'Different');
});
