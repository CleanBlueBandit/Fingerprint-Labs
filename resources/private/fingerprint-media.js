// Audio, WebGL rendering and media capability tests.
// Loaded after fingerprint-lib.js, which provides the test harness and hashing.
//
// Capability detection (what the browser exposes) and behavioural measurement (what it
// computes) are separate tests on purpose: they have different stability and different
// causes. No test here records timing.

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

const AUDIO_INTERFACES = [
    "AudioContext", "OfflineAudioContext", "BaseAudioContext", "AudioWorklet", "AudioWorkletNode",
    "AudioNode", "AudioParam", "AudioBuffer", "AudioListener", "AnalyserNode", "AudioBufferSourceNode",
    "BiquadFilterNode", "ChannelMergerNode", "ChannelSplitterNode", "ConstantSourceNode", "ConvolverNode",
    "DelayNode", "DynamicsCompressorNode", "GainNode", "IIRFilterNode", "MediaElementAudioSourceNode",
    "MediaStreamAudioDestinationNode", "MediaStreamAudioSourceNode", "MediaStreamTrackAudioSourceNode",
    "OscillatorNode", "PannerNode", "PeriodicWave", "ScriptProcessorNode", "StereoPannerNode", "WaveShaperNode"
];

// Capability detection only. Nothing here renders audio, and no live AudioContext is
// created, so no output device is opened.
async function getAudioCapabilities() {
    const AC = window.AudioContext || window.webkitAudioContext;
    const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!AC && !OAC) unsupported("neither AudioContext nor OfflineAudioContext is defined");

    const members = (ctor) => (ctor && ctor.prototype
        ? Object.getOwnPropertyNames(ctor.prototype).filter((n) => n !== "constructor").sort()
        : null);

    const interfaces = {};
    for (const name of AUDIO_INTERFACES) interfaces[name] = typeof window[name] !== "undefined";

    const contextMembers = {
        BaseAudioContext: members(window.BaseAudioContext),
        AudioContext: members(AC),
        OfflineAudioContext: members(OAC)
    };
    const factories = (contextMembers.BaseAudioContext || contextMembers.AudioContext || contextMembers.OfflineAudioContext || [])
        .filter((n) => n.startsWith("create"));

    const out = {
        prefixed: {
            AudioContext: !window.AudioContext && !!window.webkitAudioContext,
            OfflineAudioContext: !window.OfflineAudioContext && !!window.webkitOfflineAudioContext
        },
        interfaces,
        contextMembers,
        factoryMethods: factories
    };

    // Offline contexts open no device, so what they accept can be probed safely
    if (OAC) {
        const accepts = (channels, length, rate) => {
            try { return !!new OAC(channels, length, rate); } catch (e) { return false; }
        };
        out.offlineSampleRates = Object.fromEntries(
            [3000, 8000, 22050, 44100, 48000, 96000, 192000, 384000, 768000].map((r) => [r, accepts(1, 1, r)])
        );
        out.offlineChannelCounts = Object.fromEntries([1, 2, 6, 8, 32, 33].map((c) => [c, accepts(c, 1, 44100)]));

        const ctx = new OAC(1, 1, 44100);
        const accepted = (node, prop, values) => values.filter((v) => {
            try { node[prop] = v; return node[prop] === v; } catch (e) { return false; }
        });
        out.enumerations = {};
        const tryNode = (name, make, prop, values) => {
            try { out.enumerations[name] = accepted(make(), prop, values); } catch (e) { out.enumerations[name] = null; }
        };
        tryNode("oscillatorType", () => ctx.createOscillator(), "type", ["sine", "square", "sawtooth", "triangle"]);
        tryNode("biquadType", () => ctx.createBiquadFilter(), "type",
            ["lowpass", "highpass", "bandpass", "lowshelf", "highshelf", "peaking", "notch", "allpass"]);
        tryNode("pannerPanningModel", () => ctx.createPanner(), "panningModel", ["equalpower", "HRTF"]);
        tryNode("pannerDistanceModel", () => ctx.createPanner(), "distanceModel", ["linear", "inverse", "exponential"]);
        tryNode("waveShaperOversample", () => ctx.createWaveShaper(), "oversample", ["none", "2x", "4x"]);

        out.instanceFeatures = {
            audioWorklet: !!ctx.audioWorklet,
            listenerAudioParams: !!ctx.listener && "positionX" in ctx.listener
        };
    }

    return {
        raw: out,
        normalized: out,
        notes: ["Audio sample rate and latencies follow the output device and session, so they are collected under audio.output and left out of this static test."]
    };
}

const AUDIO_RENDER = { sampleRate: 44100, length: 44100 };

// Each variant is a fixed graph: same nodes, same parameters, same order, every run.
const AUDIO_VARIANTS = {
    // oscillator -> compressor. Same parameters as audio.fingerprint, so results can be compared with it.
    triangleCompressor(ctx) {
        const osc = ctx.createOscillator();
        osc.type = "triangle";
        osc.frequency.value = 10000;
        const compressor = ctx.createDynamicsCompressor();
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0;
        compressor.release.value = 0.25;
        osc.connect(compressor);
        compressor.connect(ctx.destination);
        osc.start(0);
    },
    // oscillator with parameter automation -> filter -> compressor, which exercises different code paths
    automationFilterCompressor(ctx) {
        const osc = ctx.createOscillator();
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(440, 0);
        osc.frequency.exponentialRampToValueAtTime(8000, 0.5);
        osc.frequency.linearRampToValueAtTime(1200, 1);
        const filter = ctx.createBiquadFilter();
        filter.type = "lowpass";
        filter.frequency.value = 3000;
        filter.Q.value = 5;
        const compressor = ctx.createDynamicsCompressor();
        osc.connect(filter);
        filter.connect(compressor);
        compressor.connect(ctx.destination);
        osc.start(0);
    }
};

async function renderAudioVariant(OAC, build) {
    const ctx = new OAC(1, AUDIO_RENDER.length, AUDIO_RENDER.sampleRate);
    build(ctx);
    const buffer = await ctx.startRendering();
    return buffer.getChannelData(0).slice(); // copy, so nothing later can alias the engine's buffer
}

function summarizeSamples(samples) {
    let peak = 0, sumSquares = 0, nan = 0, nonZero = 0;
    for (let i = 0; i < samples.length; i++) {
        const v = samples[i];
        if (Number.isNaN(v)) { nan++; continue; }
        const a = Math.abs(v);
        if (a > peak) peak = a;
        if (v !== 0) nonZero++;
        sumSquares += v * v;
    }
    return {
        frames: samples.length,
        peak,
        rms: Math.sqrt(sumSquares / Math.max(1, samples.length - nan)),
        nonZero,
        nan
    };
}

// Peak-normalized 16-bit quantization: removes overall gain and sub-1/32767 noise
// before hashing, so it tolerates rounding differences the raw hash does not.
function quantizeSamples(samples, peak) {
    const out = new Int16Array(samples.length);
    if (peak > 0) {
        for (let i = 0; i < samples.length; i++) out[i] = Math.round((samples[i] / peak) * 32767);
    }
    return out;
}

async function getAudioRendering() {
    const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!OAC) unsupported("OfflineAudioContext is not defined");

    const raw = { sampleRate: AUDIO_RENDER.sampleRate, frames: AUDIO_RENDER.length, variants: {} };
    const normalized = { sampleRate: AUDIO_RENDER.sampleRate, frames: AUDIO_RENDER.length, variants: {} };
    const rawHashes = {};
    let rendered = 0;

    for (const [id, build] of Object.entries(AUDIO_VARIANTS)) {
        const sub = await runSub(async () => {
            // Rendered twice in the same session. Different results mean the browser adds noise.
            const first = await renderAudioVariant(OAC, build);
            const second = await renderAudioVariant(OAC, build);
            const rawFirst = await hashBytes(first);
            const rawSecond = await hashBytes(second);
            const deterministic = rawFirst.value === rawSecond.value;

            const stats = summarizeSamples(first);
            const silent = stats.nonZero === 0;
            const quantized = await hashBytes(quantizeSamples(first, stats.peak));
            return {
                deterministic, silent, stats,
                // legacy-compatible window, to compare with audio.fingerprint.sampleSum
                windowSum4500to5000: Array.from(first.slice(4500, 5000)).reduce((s, v) => s + Math.abs(v), 0),
                rawSha256: rawFirst.value,
                quantizedSha256: quantized.value
            };
        });
        raw.variants[id] = sub;
        if (sub.status !== "success") {
            normalized.variants[id] = { status: sub.status, reason: sub.reason };
            rawHashes[id] = null;
            continue;
        }
        rendered++;
        // A noisy variant contributes no hash: its value would differ on every run
        normalized.variants[id] = {
            status: "success",
            deterministic: sub.deterministic,
            silent: sub.silent,
            quantizedSha256: sub.deterministic ? sub.quantizedSha256 : null
        };
        rawHashes[id] = sub.deterministic ? sub.rawSha256 : null;
    }

    if (!rendered) throw new Error("no audio variant could be rendered");
    return {
        raw,
        normalized,
        hashes: { rawSamples: rawHashes },
        notes: [
            "normalized.variants[*].quantizedSha256 hashes peak-normalized 16-bit samples. hashes.rawSamples hashes the exact Float32 bits and is the stricter of the two.",
            "deterministic=false means two renders in one session differed, which points to deliberate noise rather than a different device. silent=true means the engine returned zeros."
        ]
    };
}

// ---------------------------------------------------------------------------
// WebGL rendering (behavioral)
// ---------------------------------------------------------------------------

const GL_TILE = 32;
const GL_COLUMNS = 4;
const GL_ROWS = 2;
const GL_WIDTH = GL_TILE * GL_COLUMNS;
const GL_HEIGHT = GL_TILE * GL_ROWS;

function createGlContext(version) {
    const canvas = document.createElement("canvas");
    canvas.width = 16;
    canvas.height = 16;
    // Rendering goes to a framebuffer object below, so the default drawing buffer, its
    // anti-aliasing and the compositor do not take part in the measurement.
    const attrs = { alpha: true, antialias: false, depth: false, stencil: false, preserveDrawingBuffer: false };
    const gl = canvas.getContext(version === 2 ? "webgl2" : "webgl", attrs);
    return gl ? { gl, canvas } : null;
}

// Shader source for either GLSL ES 1.00 (WebGL1) or 3.00 (WebGL2)
function glShaderSources(version) {
    const es3 = version === 2;
    const vs = `${es3 ? "#version 300 es\n" : ""}` +
        `${es3 ? "in" : "attribute"} vec2 a_pos;` +
        `${es3 ? "out" : "varying"} vec2 v_uv;` +
        "uniform vec4 u_rect;" +
        "void main(){ v_uv = a_pos; gl_Position = vec4(mix(u_rect.xy, u_rect.zw, a_pos), 0.0, 1.0); }";

    const fsHead = `${es3 ? "#version 300 es\n" : ""}` +
        "#ifdef GL_FRAGMENT_PRECISION_HIGH\n#define HP highp\n#else\n#define HP mediump\n#endif\n" +
        "precision mediump float;" +
        `${es3 ? "in" : "varying"} vec2 v_uv;` +
        (es3 ? "out vec4 o_color;" : "");
    const color = es3 ? "o_color" : "gl_FragColor";
    const tex = es3 ? "texture" : "texture2D";

    // Same arithmetic at three explicit precisions. The result depends on how the GPU
    // implements sin, exp, log, pow, atan and inversesqrt at that precision.
    const mathProgram = (q) => `${fsHead}` +
        `${q} float f(${q} vec2 p){` +
        `${q} float d = dot(p, vec2(12.9898, 78.233));` +
        `${q} float s = sin(d) * 43758.5453;` +
        `${q} float x = fract(s);` +
        `${q} float e = exp(x * 3.0) + log(1.0 + abs(s)) * 0.01;` +
        `${q} float t = pow(x + 0.5, 1.7) + atan(fract(d), 1.0 + x) + inversesqrt(1.0 + fract(e));` +
        "return fract(s + e + t); }" +
        "void main(){" +
        `${q} vec2 p = gl_FragCoord.xy * 0.0123;` +
        `${color} = vec4(f(p), f(p + vec2(0.37, 0.11)), f(p.yx * 1.3), 1.0); }`;

    return {
        vertex: vs,
        programs: {
            mathHigh: mathProgram("HP"),
            mathMedium: mathProgram("mediump"),
            mathLow: mathProgram("lowp"),
            // Texture sampling: bilinear on a small texture with fractional, wrapping coordinates,
            // and trilinear minification through generated mipmaps
            texture: `${fsHead}uniform sampler2D u_tex; uniform sampler2D u_mip; uniform float u_mode;` +
                "void main(){" +
                `vec4 a = ${tex}(u_tex, v_uv * 1.37 + vec2(0.113, 0.071));` +
                `vec4 b = ${tex}(u_mip, v_uv * 5.3);` +
                `${color} = u_mode < 0.5 ? a : b; }`,
            // Transparency and blending: a gradient in colour and alpha, composited by the blend unit
            blend: `${fsHead}uniform vec4 u_color;` +
                `void main(){ ${color} = vec4(u_color.rgb * (0.5 + 0.5 * v_uv.x), u_color.a * (0.25 + 0.75 * v_uv.y)); }`
        }
    };
}

// A fixed RGBA texture: colour from integer arithmetic, alpha below 1 so transparency matters
function glTexturePixels(size) {
    const px = new Uint8Array(size * size * 4);
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            const i = (y * size + x) * 4;
            px[i] = (x * 37 + y * 91) & 255;
            px[i + 1] = (x * x * 5 + y * 13) & 255;
            px[i + 2] = ((x ^ y) * 29) & 255;
            px[i + 3] = 255 - ((x * y) & 127);
        }
    }
    return px;
}

// Which program and state each tile of the output uses
const GL_TILES = [
    { name: "floatHighp", program: "mathHigh" },
    { name: "floatMediump", program: "mathMedium" },
    { name: "floatLowp", program: "mathLow" },
    { name: "textureBilinear", program: "texture", mode: 0 },
    { name: "textureMipmap", program: "texture", mode: 1 },
    { name: "blendAlpha", program: "blend", blend: "alpha" },
    { name: "blendSeparate", program: "blend", blend: "separate" },
    { name: "blendConstant", program: "blend", blend: "constant" }
];

const BLEND_QUADS = [
    { rect: [-0.9, -0.9, 0.3, 0.3], color: [1.0, 0.1, 0.1, 0.8] },
    { rect: [-0.4, -0.5, 0.8, 0.7], color: [0.1, 1.0, 0.2, 0.55] },
    { rect: [-0.1, -0.1, 0.95, 0.95], color: [0.2, 0.3, 1.0, 0.4] }
];

function renderWebGlScene(gl, version) {
    const resources = { shaders: [], programs: [], textures: [], buffers: [], framebuffers: [] };
    const sources = glShaderSources(version);
    const report = { programs: {}, framebufferStatus: null };

    try {
        const compile = (type, src) => {
            const shader = gl.createShader(type);
            resources.shaders.push(shader);
            gl.shaderSource(shader, src);
            gl.compileShader(shader);
            if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
                throw new Error(`compile failed: ${String(gl.getShaderInfoLog(shader)).slice(0, 160)}`);
            }
            return shader;
        };
        const vertex = compile(gl.VERTEX_SHADER, sources.vertex);

        // Programs are built independently, so one failing precision does not lose the others
        const programs = {};
        for (const [name, source] of Object.entries(sources.programs)) {
            try {
                const program = gl.createProgram();
                resources.programs.push(program);
                gl.attachShader(program, vertex);
                gl.attachShader(program, compile(gl.FRAGMENT_SHADER, source));
                gl.bindAttribLocation(program, 0, "a_pos");
                gl.linkProgram(program);
                if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
                    throw new Error(`link failed: ${String(gl.getProgramInfoLog(program)).slice(0, 160)}`);
                }
                programs[name] = {
                    program,
                    rect: gl.getUniformLocation(program, "u_rect"),
                    color: gl.getUniformLocation(program, "u_color"),
                    mode: gl.getUniformLocation(program, "u_mode"),
                    tex: gl.getUniformLocation(program, "u_tex"),
                    mip: gl.getUniformLocation(program, "u_mip")
                };
                report.programs[name] = { status: "success" };
            } catch (e) {
                report.programs[name] = { status: "failed", error: String(e.message || e) };
            }
        }

        // Unit quad as a triangle strip, positioned per draw through u_rect
        const quad = gl.createBuffer();
        resources.buffers.push(quad);
        gl.bindBuffer(gl.ARRAY_BUFFER, quad);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([0, 0, 1, 0, 0, 1, 1, 1]), gl.STATIC_DRAW);
        gl.enableVertexAttribArray(0);
        gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

        // Textures: an 8x8 bilinear source and a 16x16 source with generated mipmaps
        const makeTexture = (unit, size, mipmaps) => {
            const t = gl.createTexture();
            resources.textures.push(t);
            gl.activeTexture(gl.TEXTURE0 + unit);
            gl.bindTexture(gl.TEXTURE_2D, t);
            gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);
            gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, size, size, 0, gl.RGBA, gl.UNSIGNED_BYTE, glTexturePixels(size));
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.REPEAT);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.REPEAT);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
            if (mipmaps) {
                gl.generateMipmap(gl.TEXTURE_2D);
                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
            } else {
                gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
            }
        };
        makeTexture(0, 8, false);
        makeTexture(1, 16, true);

        // Render target: an RGBA8 texture, read back with readPixels
        const target = gl.createTexture();
        resources.textures.push(target);
        gl.activeTexture(gl.TEXTURE2);
        gl.bindTexture(gl.TEXTURE_2D, target);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, GL_WIDTH, GL_HEIGHT, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        const fbo = gl.createFramebuffer();
        resources.framebuffers.push(fbo);
        gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
        gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, target, 0);
        report.framebufferStatus = gl.checkFramebufferStatus(gl.FRAMEBUFFER) === gl.FRAMEBUFFER_COMPLETE ? "complete" : "incomplete";
        if (report.framebufferStatus !== "complete") throw new Error("framebuffer is incomplete");

        const draw = (u, rect) => {
            gl.uniform4f(u.rect, rect[0], rect[1], rect[2], rect[3]);
            gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
        };

        const renderOnce = () => {
            gl.disable(gl.SCISSOR_TEST);
            gl.disable(gl.BLEND);
            gl.viewport(0, 0, GL_WIDTH, GL_HEIGHT);
            gl.clearColor(0, 0, 0, 0);
            gl.clear(gl.COLOR_BUFFER_BIT);
            gl.enable(gl.SCISSOR_TEST);

            GL_TILES.forEach((tile, index) => {
                const entry = programs[tile.program];
                if (!entry) return; // this tile's program failed to build: left transparent black
                const x = (index % GL_COLUMNS) * GL_TILE;
                const y = Math.floor(index / GL_COLUMNS) * GL_TILE;
                gl.viewport(x, y, GL_TILE, GL_TILE);
                gl.scissor(x, y, GL_TILE, GL_TILE);
                gl.clearColor(0.2, 0.4, 0.6, 0.5);
                gl.clear(gl.COLOR_BUFFER_BIT);
                gl.useProgram(entry.program);
                if (entry.tex) gl.uniform1i(entry.tex, 0);
                if (entry.mip) gl.uniform1i(entry.mip, 1);
                if (entry.mode) gl.uniform1f(entry.mode, tile.mode || 0);

                if (tile.blend) {
                    gl.enable(gl.BLEND);
                    if (tile.blend === "alpha") {
                        gl.blendEquation(gl.FUNC_ADD);
                        gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
                    } else if (tile.blend === "separate") {
                        gl.blendEquationSeparate(gl.FUNC_REVERSE_SUBTRACT, gl.FUNC_ADD);
                        gl.blendFuncSeparate(gl.SRC_ALPHA, gl.ONE, gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
                    } else {
                        gl.blendEquation(gl.FUNC_ADD);
                        gl.blendColor(0.25, 0.5, 0.75, 0.5);
                        gl.blendFunc(gl.CONSTANT_COLOR, gl.ONE_MINUS_CONSTANT_COLOR);
                    }
                    for (const q of BLEND_QUADS) {
                        gl.uniform4f(entry.color, q.color[0], q.color[1], q.color[2], q.color[3]);
                        draw(entry, q.rect);
                    }
                    gl.disable(gl.BLEND);
                } else {
                    draw(entry, [-1, -1, 1, 1]);
                }
            });
            gl.finish();

            const pixels = new Uint8Array(GL_WIDTH * GL_HEIGHT * 4);
            gl.readPixels(0, 0, GL_WIDTH, GL_HEIGHT, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
            return pixels;
        };

        const first = renderOnce();
        const second = renderOnce();
        const error = gl.getError();
        return { first, second, report, glError: error === gl.NO_ERROR ? null : error };
    } finally {
        // Always release everything, whatever happened above
        const safeCall = (fn) => { try { fn(); } catch (e) { /* ignore */ } };
        resources.framebuffers.forEach((r) => safeCall(() => gl.deleteFramebuffer(r)));
        resources.textures.forEach((r) => safeCall(() => gl.deleteTexture(r)));
        resources.buffers.forEach((r) => safeCall(() => gl.deleteBuffer(r)));
        resources.programs.forEach((r) => safeCall(() => gl.deleteProgram(r)));
        resources.shaders.forEach((r) => safeCall(() => gl.deleteShader(r)));
        safeCall(() => gl.bindFramebuffer(gl.FRAMEBUFFER, null));
    }
}

// Copies one tile out of the full-frame readback
function glExtractTile(pixels, index) {
    const x = (index % GL_COLUMNS) * GL_TILE;
    const y = Math.floor(index / GL_COLUMNS) * GL_TILE;
    const tile = new Uint8Array(GL_TILE * GL_TILE * 4);
    for (let row = 0; row < GL_TILE; row++) {
        const from = ((y + row) * GL_WIDTH + x) * 4;
        tile.set(pixels.subarray(from, from + GL_TILE * 4), row * GL_TILE * 4);
    }
    return tile;
}

function glTileStats(tile) {
    const sums = [0, 0, 0, 0];
    const colors = new Set();
    for (let i = 0; i < tile.length; i += 4) {
        for (let c = 0; c < 4; c++) sums[c] += tile[i + c];
        colors.add((tile[i] << 24) | (tile[i + 1] << 16) | (tile[i + 2] << 8) | tile[i + 3]);
    }
    const n = tile.length / 4;
    return { mean: sums.map((s) => Number((s / n).toFixed(3))), distinctColors: colors.size };
}

// Coarser than the raw bytes: 6 bits per channel, so one-level rounding differences collapse
const glQuantize = (tile) => Uint8Array.from(tile, (v) => v >> 2);

async function runWebGlRenderVariant(version) {
    const created = createGlContext(version);
    if (!created) {
        const API = version === 2 ? "WebGL2RenderingContext" : "WebGLRenderingContext";
        if (typeof window[API] === "undefined") unsupported(`${API} is not defined`);
        unavailable("context creation failed (WebGL disabled, GPU blocklisted or context limit reached)");
    }
    const { gl, canvas } = created;
    try {
        const { first, second, report, glError } = renderWebGlScene(gl, version);
        const fragmentHigh = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);

        // Readback that is entirely zero (not even the 0.5 clear alpha) means it was blocked
        if (!first.some((v) => v !== 0)) unavailable("readPixels returned only zeros (readback blocked or stubbed)");

        const rawHashFirst = (await hashBytes(first)).value;
        const rawHashSecond = (await hashBytes(second)).value;
        const deterministic = rawHashFirst === rawHashSecond;

        const tiles = {};
        const normalizedTiles = {};
        for (let i = 0; i < GL_TILES.length; i++) {
            const name = GL_TILES[i].name;
            const programStatus = report.programs[GL_TILES[i].program];
            if (!programStatus || programStatus.status !== "success") {
                tiles[name] = { status: "failed", error: programStatus && programStatus.error };
                normalizedTiles[name] = { status: "failed" };
                continue;
            }
            const tile = glExtractTile(first, i);
            const rawHash = (await hashBytes(tile)).value;
            const quantized = (await hashBytes(glQuantize(tile))).value;
            tiles[name] = { status: "success", rawSha256: rawHash, quantizedSha256: quantized, ...glTileStats(tile) };
            normalizedTiles[name] = { status: "success", quantizedSha256: deterministic ? quantized : null };
        }

        const raw = {
            deterministic,
            fragmentHighpPrecisionBits: fragmentHigh ? fragmentHigh.precision : null,
            framebufferStatus: report.framebufferStatus,
            glError,
            frame: { width: GL_WIDTH, height: GL_HEIGHT, rawSha256: rawHashFirst },
            tiles,
            programs: report.programs
        };
        const normalized = {
            deterministic,
            fragmentHighpAvailable: !!(fragmentHigh && fragmentHigh.precision > 0),
            tiles: normalizedTiles,
            frameQuantizedSha256: deterministic ? (await hashBytes(glQuantize(first))).value : null
        };
        return { raw, normalized, rawFrameHash: deterministic ? rawHashFirst : null };
    } finally {
        // Release the context itself rather than waiting for garbage collection
        try {
            const lose = gl.getExtension("WEBGL_lose_context");
            if (lose) lose.loseContext();
        } catch (e) { /* ignore */ }
        canvas.width = 0;
        canvas.height = 0;
    }
}

async function getWebGlRendering() {
    const raw = {}, normalized = {}, rawHashes = {};
    let succeeded = 0;
    const blocked = [];
    for (const [key, version] of [["webgl", 1], ["webgl2", 2]]) {
        const sub = await runSub(() => runWebGlRenderVariant(version));
        if (sub.status === "success") {
            succeeded++;
            raw[key] = { status: "success", ...sub.raw };
            normalized[key] = { status: "success", ...sub.normalized };
            rawHashes[key] = sub.rawFrameHash;
        } else {
            raw[key] = sub;
            normalized[key] = { status: sub.status };
            rawHashes[key] = null;
            blocked.push(`${key}: ${sub.status}${sub.reason ? ` (${sub.reason})` : ""}`);
        }
    }
    if (!succeeded) {
        const statuses = Object.values(raw).map((r) => r.status);
        if (statuses.every((s) => s === "unsupported")) unsupported("WebGL is not defined");
        if (statuses.includes("failed")) throw new Error(blocked.join("; "));
        unavailable(blocked.join("; "));
    }
    return {
        raw,
        normalized,
        hashes: { rawFrames: rawHashes },
        notes: [
            "Each tile is a separate measurement: highp, mediump and lowp float maths, bilinear and mipmapped texture sampling, and three blend set-ups. Compare tiles to see which stage differs.",
            "Rendering goes to an offscreen framebuffer and is read with readPixels. Results are not guaranteed identical across driver or browser updates, and identical hardware can differ.",
            "A tile that is failed or an unavailable variant is excluded from comparisons rather than treated as a different device. deterministic=false means two renders in one session differed (noise injection)."
        ]
    };
}

// ---------------------------------------------------------------------------
// MediaCapabilities and WebCodecs (static, with hardware hints)
// ---------------------------------------------------------------------------

// Fixed configurations: the same list every run, so sessions can be compared.
const MEDIA_VIDEO_CODECS = [
    { id: "h264-baseline", mime: "video/mp4", codec: "avc1.42E01E" },
    { id: "h264-main", mime: "video/mp4", codec: "avc1.4D401F" },
    { id: "h264-high", mime: "video/mp4", codec: "avc1.640028" },
    { id: "hevc-main", mime: "video/mp4", codec: "hvc1.1.6.L93.B0" },
    { id: "hevc-main10", mime: "video/mp4", codec: "hvc1.2.4.L120.B0" },
    { id: "vp8", mime: "video/webm", codec: "vp8" },
    { id: "vp9-profile0", mime: "video/webm", codec: "vp09.00.10.08" },
    { id: "vp9-profile2", mime: "video/webm", codec: "vp09.02.10.10" },
    { id: "av1-main-8bit", mime: "video/mp4", codec: "av01.0.05M.08" },
    { id: "av1-main-10bit", mime: "video/mp4", codec: "av01.0.08M.10" }
];
const MEDIA_RESOLUTIONS = [
    { id: "360p30", width: 640, height: 360, framerate: 30, bitrate: 1000000 },
    { id: "720p30", width: 1280, height: 720, framerate: 30, bitrate: 3000000 },
    { id: "1080p30", width: 1920, height: 1080, framerate: 30, bitrate: 6000000 },
    { id: "1080p60", width: 1920, height: 1080, framerate: 60, bitrate: 10000000 },
    { id: "2160p30", width: 3840, height: 2160, framerate: 30, bitrate: 20000000 },
    { id: "2160p60", width: 3840, height: 2160, framerate: 60, bitrate: 35000000 }
];
const MEDIA_AUDIO_CODECS = [
    { id: "aac-lc", contentType: 'audio/mp4; codecs="mp4a.40.2"' },
    { id: "opus", contentType: 'audio/webm; codecs="opus"' },
    { id: "vorbis", contentType: 'audio/ogg; codecs="vorbis"' },
    { id: "flac", contentType: "audio/flac" },
    { id: "mp3", contentType: "audio/mpeg" },
    { id: "eac3", contentType: 'audio/mp4; codecs="ec-3"' }
];
const WEBCODECS_VIDEO = MEDIA_VIDEO_CODECS.map((c) => ({ id: c.id, codec: c.codec }));
const WEBCODECS_AUDIO = [
    { id: "opus", codec: "opus" }, { id: "aac-lc", codec: "mp4a.40.2" }, { id: "flac", codec: "flac" },
    { id: "mp3", codec: "mp3" }, { id: "vorbis", codec: "vorbis" }
];
const IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp", "image/avif", "image/jxl", "image/bmp", "image/x-icon", "image/svg+xml"];

// One decodingInfo() call, reduced to a result that is the same shape every time
async function decodingInfoEntry(config) {
    try {
        const info = await withTimeout(navigator.mediaCapabilities.decodingInfo(config), 5000, "decodingInfo");
        return { supported: !!info.supported, smooth: !!info.smooth, powerEfficient: !!info.powerEfficient };
    } catch (e) {
        // A TypeError means the browser does not recognise the configuration at all
        return { error: (e && e.name) || "Error" };
    }
}

// Runs async tasks a few at a time, so dozens of decodingInfo() calls do not pile up
async function inBatches(tasks, size = 6) {
    const results = [];
    for (let i = 0; i < tasks.length; i += size) {
        results.push(...await Promise.all(tasks.slice(i, i + size).map((t) => t())));
    }
    return results;
}

const flag = (entry, key) => (entry.error ? "e" : entry[key] ? "1" : "0");

async function getMediaCapabilities() {
    const hasMc = !!(navigator.mediaCapabilities && navigator.mediaCapabilities.decodingInfo);
    const hasCodecs = typeof window.VideoDecoder !== "undefined" || typeof window.VideoEncoder !== "undefined";
    if (!hasMc && !hasCodecs) unsupported("neither MediaCapabilities nor WebCodecs is defined");

    const raw = { mediaCapabilities: null, webCodecs: null };
    const normalized = { mediaCapabilities: null, webCodecs: null };
    const smoothBitmap = {};
    const powerBitmap = {};

    if (hasMc) {
        // Video: every codec at every resolution as a file, plus 1080p30 as media-source
        const jobs = [];
        for (const c of MEDIA_VIDEO_CODECS) {
            for (const r of MEDIA_RESOLUTIONS) jobs.push({ key: `video/file/${c.id}/${r.id}`, type: "file", c, r });
            const r = MEDIA_RESOLUTIONS.find((x) => x.id === "1080p30");
            jobs.push({ key: `video/media-source/${c.id}/${r.id}`, type: "media-source", c, r });
        }
        const entries = await inBatches(jobs.map((j) => () => decodingInfoEntry({
            type: j.type,
            video: {
                contentType: `${j.c.mime}; codecs="${j.c.codec}"`,
                width: j.r.width, height: j.r.height, bitrate: j.r.bitrate, framerate: j.r.framerate
            }
        })));
        const audioEntries = await inBatches(MEDIA_AUDIO_CODECS.map((a) => () => decodingInfoEntry({
            type: "file",
            audio: { contentType: a.contentType, channels: "2", bitrate: 128000, samplerate: 48000 }
        })));

        const results = {};
        jobs.forEach((j, i) => { results[j.key] = entries[i]; });
        MEDIA_AUDIO_CODECS.forEach((a, i) => { results[`audio/file/${a.id}`] = audioEntries[i]; });
        raw.mediaCapabilities = results;

        // supported, smooth and powerEfficient are kept as three separate maps
        const supported = {};
        for (const [key, entry] of Object.entries(results)) {
            supported[key] = flag(entry, "supported");
            smoothBitmap[key] = flag(entry, "smooth");
            powerBitmap[key] = flag(entry, "powerEfficient");
        }
        // Summaries per codec: the highest resolution that is supported, for readability
        const maxSupported = {};
        for (const c of MEDIA_VIDEO_CODECS) {
            const ok = MEDIA_RESOLUTIONS.filter((r) => supported[`video/file/${c.id}/${r.id}`] === "1");
            maxSupported[c.id] = ok.length ? ok[ok.length - 1].id : null;
        }
        normalized.mediaCapabilities = { supported, maxSupportedResolution: maxSupported };
        if (Object.values(results).every((e) => e.error)) {
            normalized.mediaCapabilities = { status: "failed", errors: Array.from(new Set(Object.values(results).map((e) => e.error))).sort() };
        }
    }

    if (hasCodecs) {
        const wc = {};
        const probe = async (api, config) => {
            try {
                const r = await withTimeout(api.isConfigSupported(config), 5000, "isConfigSupported");
                return r && r.supported ? "1" : "0";
            } catch (e) {
                return "e";
            }
        };
        wc.interfaces = Object.fromEntries(
            ["VideoDecoder", "VideoEncoder", "AudioDecoder", "AudioEncoder", "ImageDecoder", "VideoFrame", "AudioData", "EncodedVideoChunk", "EncodedAudioChunk", "ImageTrackList"]
                .map((n) => [n, typeof window[n] !== "undefined"])
        );
        // The same codec asked three ways shows what the hardware path accepts. Chromium returns
        // unsupported for prefer-hardware when no hardware decoder exists; other engines may only treat it as a hint.
        const hardwareModes = ["no-preference", "prefer-hardware", "prefer-software"];
        wc.videoDecoder = {};
        wc.videoEncoder = {};
        for (const c of WEBCODECS_VIDEO) {
            wc.videoDecoder[c.id] = {};
            wc.videoEncoder[c.id] = {};
            for (const mode of hardwareModes) {
                if (window.VideoDecoder) {
                    wc.videoDecoder[c.id][mode] = await probe(VideoDecoder, { codec: c.codec, codedWidth: 1920, codedHeight: 1080, hardwareAcceleration: mode });
                }
                if (window.VideoEncoder) {
                    wc.videoEncoder[c.id][mode] = await probe(VideoEncoder, { codec: c.codec, width: 1280, height: 720, bitrate: 2000000, framerate: 30, hardwareAcceleration: mode });
                }
            }
        }
        wc.audioDecoder = {};
        wc.audioEncoder = {};
        for (const a of WEBCODECS_AUDIO) {
            if (window.AudioDecoder) wc.audioDecoder[a.id] = await probe(AudioDecoder, { codec: a.codec, sampleRate: 48000, numberOfChannels: 2 });
            if (window.AudioEncoder) wc.audioEncoder[a.id] = await probe(AudioEncoder, { codec: a.codec, sampleRate: 48000, numberOfChannels: 2, bitrate: 128000 });
        }
        wc.imageTypes = {};
        if (window.ImageDecoder && typeof ImageDecoder.isTypeSupported === "function") {
            for (const t of IMAGE_TYPES) {
                try { wc.imageTypes[t] = !!(await withTimeout(ImageDecoder.isTypeSupported(t), 3000, "isTypeSupported")); }
                catch (e) { wc.imageTypes[t] = null; }
            }
        }
        raw.webCodecs = wc;
        normalized.webCodecs = wc;
    }

    return {
        raw,
        // supported flags and WebCodecs configuration support: stable facts about the decoder set
        normalized,
        // History- and power-dependent results are hashed on their own and never mixed into the main hash
        hashes: { smooth: smoothBitmap, powerEfficient: powerBitmap },
        notes: [
            "supported is the capability. smooth and powerEfficient are estimates that can depend on playback history, power source and the hardware decoder in use, so they have their own hashes (hashes.smooth, hashes.powerEfficient) and are not part of the test hash.",
            "powerEfficient true usually means hardware decoding, and WebCodecs prefer-hardware support is a second view of the same fact. Neither identifies the GPU by name.",
            "Result letters: 1 = true, 0 = false, e = the browser rejected the configuration."
        ]
    };
}

registerTest({ id: "audioCapabilities", category: "static", groups: ["audioStack", "browserEngine"], run: getAudioCapabilities });
registerTest({ id: "audioRendering", category: "behavioral", groups: ["audioStack"], run: getAudioRendering, timeoutMs: 15000 });
registerTest({ id: "webglRendering", category: "behavioral", groups: ["gpu"], run: getWebGlRendering, timeoutMs: 15000 });
registerTest({ id: "mediaCapabilities", category: "static", groups: ["gpu", "browserEngine"], run: getMediaCapabilities, timeoutMs: 40000 });
