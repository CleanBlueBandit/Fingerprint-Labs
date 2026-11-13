// Weighted similarity between two saved fingerprint results. Pure functions, no database.
//
// A fingerprint is split into named components (canvas, fonts, WebGL, ...). Each component
// gets a similarity between 0 and 1 and a weight; the overall score is the weighted average
// over the components that could be compared on both sides.
//
// Weights (0-10) reflect how identifying and how stable a signal is, and are deliberately
// kept in one table so they are easy to tune:
//   - high: rendering and hardware-derived signals that rarely change on one machine
//     (canvas, WebGL, installed fonts, GPU rendering)
//   - medium: configuration that identifies a setup but changes on updates or by choice
//     (user agent, screen, languages, codecs)
//   - low: things that are shared by many users or change often (IP address, locale formats)
// Signals in one correlation group (the GPU, for example) are not independent, so a GPU
// change moves several components at once. That is intended: it is one real change.

export const VERDICTS = [
    [99.5, 'Identical'],
    [90, 'Very similar'],
    [70, 'Similar'],
    [40, 'Partly similar'],
    [0, 'Different']
];

export const GROUP_LABELS = {
    browser: 'Browser and locale',
    display: 'Display',
    hardware: 'Hardware',
    gpu: 'GPU',
    audio: 'Audio',
    rendering: 'Canvas, fonts and text',
    engine: 'Engine and media',
    advanced: 'Advanced tests',
    network: 'Network (changes with connection)'
};

const get = (obj, path) => path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);

const hasError = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && 'error' in v;

// id, label, group, weight, pick(data) -> value. undefined / null / { error } means "not comparable".
const C = (id, label, group, weight, pick) => ({ id, label, group, weight, pick });
const at = (path) => (d) => get(d, path);

const STATIC_COMPONENTS = [
    // Browser and locale
    C('userAgent', 'User agent', 'browser', 4, at('browser.userAgent')),
    C('platform', 'Platform', 'browser', 3, at('browser.platform')),
    C('languages', 'Languages', 'browser', 3, at('browser.languages')),
    C('timezone', 'Time zone', 'browser', 3, at('browser.timezone')),
    C('clientHints', 'Client hints', 'browser', 4, at('clientHints')),
    C('apis', 'Supported APIs', 'browser', 3, at('apis')),
    C('plugins', 'Plugins', 'browser', 2, at('plugins')),
    C('prefsAndLocale', 'Locale formatting', 'browser', 2, at('prefsAndLocale')),

    // Display
    C('screen', 'Screen', 'display', 5, at('display.screen')),
    C('devicePixelRatio', 'Device pixel ratio', 'display', 2, at('display.devicePixelRatio')),
    // orientation, display mode and overflow depend on the window, not the device
    C('mediaFeatures', 'CSS media features', 'display', 3, (d) => {
        const m = d.mediaFeatures;
        return m && typeof m === 'object' ? { ...m, volatile: undefined } : m;
    }),

    // Hardware
    C('hardware', 'Hardware (cores, memory, touch)', 'hardware', 5, at('hardware')),

    // GPU
    C('webgl', 'WebGL (vendor, renderer, limits)', 'gpu', 9, at('webgl')),
    C('webglRendering', 'WebGL rendering', 'gpu', 6, (d) => testValue(d, 'webglRendering')),
    C('webgpu', 'WebGPU adapter', 'gpu', 5, at('webgpu')),
    C('webgpuRendering', 'WebGPU rendering', 'gpu', 6, at('webgpuRendering.hash')),

    // Audio
    C('audioFingerprint', 'Audio fingerprint', 'audio', 6, at('audio.fingerprint')),
    C('audioRendering', 'Audio rendering', 'audio', 4, (d) => testValue(d, 'audioRendering')),
    C('audioSupport', 'Audio capabilities', 'audio', 2, at('audio.support')),
    // latencies and state follow the output device and the session
    C('audioOutput', 'Audio output', 'audio', 2, (d) => {
        const o = d.audio?.output;
        return o && !o.error ? { sampleRate: o.sampleRate, destination: o.destination, analyser: o.analyser } : undefined;
    }),

    // Canvas, fonts and text
    C('canvas', 'Canvas', 'rendering', 8, (d) => d.canvas?.hash ?? d.canvas),
    C('fonts', 'Installed fonts', 'rendering', 8, at('fonts.installed')),
    C('textRendering', 'Text and emoji rendering', 'rendering', 5, at('textRendering.hash')),

    // Engine and media
    C('jsEngine', 'JavaScript engine behaviour', 'engine', 4, at('jsEngine.hash')),
    C('cssFeatures', 'CSS features', 'engine', 4, at('cssFeatures')),
    C('codecs', 'Media codecs', 'engine', 4, at('codecs')),
    C('speechVoices', 'Speech voices', 'engine', 4, at('speechVoices')),

    // Network: low weight, because it changes whenever the connection does
    C('requestShape', 'HTTP request shape (header order, Accept)', 'network', 3, at('serverView.signature')),
    C('ja4', 'TLS fingerprint (JA4)', 'network', 3, at('serverView.tlsFingerprint.ja4')),
    C('ip', 'IP address', 'network', 1, at('serverView.ip.client.address'))
];

// Weights for the registered tests under result.tests. Anything not listed gets a weight from
// its category. The tests that duplicate a component above are listed separately there.
const TEST_WEIGHTS = {
    fontAnalysis: 5,
    mediaCapabilities: 3,
    wasmCapabilities: 2,
    wasmComputation: 2,
    screenDetails: 2,
    hardwareEnvironment: 1,
    browserSettings: 1,
    storageEnvironment: 1
};
const TEST_CATEGORY_WEIGHTS = { static: 2, configuration: 1.5, behavioral: 3 };
// Already compared above under their own component
const TESTS_HANDLED_ELSEWHERE = new Set(['webglRendering', 'audioRendering']);

// A test counts as a stable value only when it ran. "unsupported" is a stable fact about the
// browser; "unavailable" and "failed" depend on permissions and timing, so they are skipped.
function testValue(data, id) {
    const t = data?.tests?.[id];
    if (!t) return undefined;
    if (t.status === 'success') return t.hash ?? undefined;
    if (t.status === 'unsupported') return 'unsupported';
    return undefined;
}

function testComponents(a, b) {
    const ids = new Set([...Object.keys(a?.tests ?? {}), ...Object.keys(b?.tests ?? {})]);
    const out = [];
    for (const id of [...ids].sort()) {
        if (TESTS_HANDLED_ELSEWHERE.has(id)) continue;
        const t = a?.tests?.[id] ?? b?.tests?.[id];
        const weight = TEST_WEIGHTS[id] ?? TEST_CATEGORY_WEIGHTS[t?.category] ?? 2;
        out.push(C(`test:${id}`, `Test: ${id}`, 'advanced', weight, (d) => testValue(d, id)));
    }
    return out;
}

// ---------------------------------------------------------------------------

export function stableStringify(value) {
    if (value === undefined) return 'undefined';
    if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? String(value);
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);

const MAX_CHANGES = 8;

// 0..1. Arrays are compared as sets (Jaccard), objects key by key, everything else exactly.
// `changes` collects where the two differ so the UI can say what moved.
function similarity(a, b, path, changes) {
    const note = (text) => { if (changes.length < MAX_CHANGES) changes.push(text); };

    if (a === b) return 1;
    const ka = kind(a);
    if (ka !== kind(b)) { note(path); return 0; }

    if (ka === 'array') {
        const sa = new Set(a.map(stableStringify));
        const sb = new Set(b.map(stableStringify));
        let shared = 0;
        for (const item of sa) if (sb.has(item)) shared += 1;
        const union = sa.size + sb.size - shared;
        if (union === 0) return 1;
        if (shared < union) note(`${path} (+${sb.size - shared} / -${sa.size - shared})`);
        return shared / union;
    }

    if (ka === 'object') {
        const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
        let total = 0;
        let count = 0;
        for (const key of keys) {
            if (a[key] === undefined && b[key] === undefined) continue;
            count += 1;
            total += similarity(a[key], b[key], path ? `${path}.${key}` : key, changes);
        }
        return count === 0 ? 1 : total / count;
    }

    if (ka === 'number' && Number.isNaN(a) && Number.isNaN(b)) return 1;
    note(path);
    return 0;
}

const comparable = (v) => v !== undefined && v !== null && !hasError(v);

export function verdictFor(score) {
    return VERDICTS.find(([min]) => score >= min)[1];
}

const round = (n, digits) => Math.round(n * 10 ** digits) / 10 ** digits;

// compareFingerprints(dataA, dataB) -> { score, verdict, coverage, components, groups }
export function compareFingerprints(a, b) {
    const components = [];
    let weightSum = 0;
    let weighted = 0;
    let allWeight = 0;
    const groups = {};

    for (const c of [...STATIC_COMPONENTS, ...testComponents(a, b)]) {
        allWeight += c.weight;
        const va = c.pick(a ?? {});
        const vb = c.pick(b ?? {});
        const entry = { id: c.id, label: c.label, group: c.group, weight: c.weight };

        if (!comparable(va) || !comparable(vb)) {
            components.push({ ...entry, status: 'skipped', similarity: null, changed: [] });
            continue;
        }

        const changes = [];
        const s = similarity(va, vb, '', changes);
        const status = s === 1 ? 'same' : s === 0 ? 'different' : 'partial';
        components.push({ ...entry, status, similarity: round(s, 4), changed: changes });

        weightSum += c.weight;
        weighted += c.weight * s;
        const g = (groups[c.group] ??= { label: GROUP_LABELS[c.group] ?? c.group, weight: 0, weighted: 0 });
        g.weight += c.weight;
        g.weighted += c.weight * s;
    }

    const score = weightSum > 0 ? round((weighted / weightSum) * 100, 1) : null;

    return {
        score,
        verdict: score === null ? null : verdictFor(score),
        // Share of the total weight that could be compared. Low means few signals were present
        // on both sides (for example one run skipped the network data), so read the score with care.
        coverage: allWeight > 0 ? round(weightSum / allWeight, 3) : 0,
        groups: Object.fromEntries(
            Object.entries(groups).map(([id, g]) => [id, {
                label: g.label,
                weight: g.weight,
                score: round((g.weighted / g.weight) * 100, 1)
            }])
        ),
        components
    };
}
