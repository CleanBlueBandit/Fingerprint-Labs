// WebAssembly capability detection and deterministic computation tests.
// Loaded after fingerprint-lib.js, which provides the test harness and hashing.
//
// Modules are assembled at runtime from the small builder below instead of being
// pasted in as opaque byte arrays, so every opcode used here can be read and reviewed.
// No execution time is recorded anywhere in this file.

// ---------------------------------------------------------------------------
// Module builder (just enough of the binary format for these tests)
// ---------------------------------------------------------------------------

const WT = { i32: 0x7f, i64: 0x7e, f32: 0x7d, f64: 0x7c, v128: 0x7b };

const seq = (...parts) => parts.flat(Infinity);

// LEB128 encoders (numbers or BigInt)
function wasmU(value) {
    let n = BigInt(value);
    const out = [];
    do {
        let byte = Number(n & 0x7fn);
        n >>= 7n;
        if (n !== 0n) byte |= 0x80;
        out.push(byte);
    } while (n !== 0n);
    return out;
}

function wasmS(value) {
    let n = BigInt(value);
    const out = [];
    for (;;) {
        const byte = Number(n & 0x7fn);
        n >>= 7n; // arithmetic shift for negative values
        const done = (n === 0n && !(byte & 0x40)) || (n === -1n && (byte & 0x40));
        out.push(done ? byte : byte | 0x80);
        if (done) return out;
    }
}

const wasmVec = (items) => [...wasmU(items.length), ...items.flat()];
const wasmName = (text) => wasmVec(Array.from(new TextEncoder().encode(text), (b) => [b]));
const wasmSection = (id, bytes) => [id, ...wasmU(bytes.length), ...bytes];

function wasmLimits({ min, max, shared }) {
    if (shared) return [0x03, ...wasmU(min), ...wasmU(max)]; // shared memories need a maximum
    return max === undefined ? [0x00, ...wasmU(min)] : [0x01, ...wasmU(min), ...wasmU(max)];
}

/**
 * wasmModule({
 *   types:   [{ params: [WT.i32], results: [WT.i32] }],
 *   imports: [{ module, name, memory: { min, max, shared } }],
 *   memory:  { min, max, shared } | null,
 *   funcs:   [{ type: 0, locals: [[1, WT.i32]], body: [...], export: "name" }]
 * }) -> Uint8Array. The final `end` of each body is added here.
 */
function wasmModule({ types = [], imports = [], memory = null, funcs = [] }) {
    const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    if (types.length) {
        bytes.push(...wasmSection(1, wasmVec(types.map((t) => [0x60, ...wasmVec(t.params.map((p) => [p])), ...wasmVec(t.results.map((r) => [r]))]))));
    }
    if (imports.length) {
        bytes.push(...wasmSection(2, wasmVec(imports.map((i) => [...wasmName(i.module), ...wasmName(i.name), 0x02, ...wasmLimits(i.memory)]))));
    }
    if (funcs.length) bytes.push(...wasmSection(3, wasmVec(funcs.map((f) => wasmU(f.type)))));
    if (memory) bytes.push(...wasmSection(5, wasmVec([wasmLimits(memory)])));
    const exported = funcs.map((f, index) => ({ f, index })).filter(({ f }) => f.export);
    if (exported.length) {
        bytes.push(...wasmSection(7, wasmVec(exported.map(({ f, index }) => [...wasmName(f.export), 0x00, ...wasmU(index)]))));
    }
    if (funcs.length) {
        bytes.push(...wasmSection(10, wasmVec(funcs.map((f) => {
            const body = [...wasmVec((f.locals || []).map(([count, type]) => [...wasmU(count), type])), ...f.body, 0x0b];
            return [...wasmU(body.length), ...body];
        }))));
    }
    return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Instruction helpers (opcode numbers from the WebAssembly spec)
// ---------------------------------------------------------------------------

const f32Bytes = (x) => Array.from(new Uint8Array(new Float32Array([x]).buffer));
const f64Bytes = (x) => Array.from(new Uint8Array(new Float64Array([x]).buffer));

const W = {
    // control
    block: [0x02, 0x40], loop: [0x03, 0x40], end: 0x0b,
    br: (depth) => [0x0c, ...wasmU(depth)],
    brIf: (depth) => [0x0d, ...wasmU(depth)],
    drop: 0x1a,
    // variables
    get: (i) => [0x20, ...wasmU(i)],
    set: (i) => [0x21, ...wasmU(i)],
    // constants
    i32: (n) => [0x41, ...wasmS(n | 0)],
    i64: (n) => [0x42, ...wasmS(BigInt.asIntN(64, BigInt(n)))],
    f32: (x) => [0x43, ...f32Bytes(x)],
    f64: (x) => [0x44, ...f64Bytes(x)],
    v128: (lanes32) => [0xfd, 0x0c, ...lanes32.flatMap((l) => Array.from(new Uint8Array(new Uint32Array([l >>> 0]).buffer)))],
    // i32
    i32eqz: 0x45, i32geU: 0x4f, i32ltU: 0x49,
    i32clz: 0x67, i32ctz: 0x68, i32popcnt: 0x69,
    i32add: 0x6a, i32sub: 0x6b, i32mul: 0x6c, i32divS: 0x6d, i32divU: 0x6e, i32remS: 0x6f, i32remU: 0x70,
    i32and: 0x71, i32or: 0x72, i32xor: 0x73, i32shl: 0x74, i32shrS: 0x75, i32shrU: 0x76, i32rotl: 0x77, i32rotr: 0x78,
    // i64
    i64geU: 0x5a,
    i64clz: 0x79, i64ctz: 0x7a, i64popcnt: 0x7b,
    i64add: 0x7c, i64sub: 0x7d, i64mul: 0x7e, i64divS: 0x7f, i64divU: 0x80, i64remS: 0x81, i64remU: 0x82,
    i64and: 0x83, i64or: 0x84, i64xor: 0x85, i64shl: 0x86, i64shrS: 0x87, i64shrU: 0x88, i64rotl: 0x89, i64rotr: 0x8a,
    // f32
    f32abs: 0x8b, f32neg: 0x8c, f32ceil: 0x8d, f32floor: 0x8e, f32trunc: 0x8f, f32nearest: 0x90, f32sqrt: 0x91,
    f32add: 0x92, f32sub: 0x93, f32mul: 0x94, f32div: 0x95, f32min: 0x96, f32max: 0x97, f32copysign: 0x98,
    // f64
    f64abs: 0x99, f64neg: 0x9a, f64ceil: 0x9b, f64floor: 0x9c, f64trunc: 0x9d, f64nearest: 0x9e, f64sqrt: 0x9f,
    f64add: 0xa0, f64sub: 0xa1, f64mul: 0xa2, f64div: 0xa3, f64min: 0xa4, f64max: 0xa5, f64copysign: 0xa6,
    // conversions
    i64extendI32U: 0xad, f64convertI32U: 0xb8, f32convertI32U: 0xb3,
    i32reinterpretF32: 0xbc, i64reinterpretF64: 0xbd,
    i32truncSatF64S: [0xfc, 0x02], i32truncSatF64U: [0xfc, 0x03],
    i32truncF64S: 0xaa,
    // SIMD (0xfd prefix, opcode as LEB128)
    i32x4splat: [0xfd, 0x11], f32x4splat: [0xfd, 0x13],
    i32x4extract: (lane) => [0xfd, 0x1b, lane],
    f32x4extract: (lane) => [0xfd, 0x1f, lane],
    v128xor: [0xfd, 0x51],
    i32x4shl: [0xfd, 0xab, 0x01], i32x4shrU: [0xfd, 0xad, 0x01],
    i32x4add: [0xfd, 0xae, 0x01], i32x4mul: [0xfd, 0xb5, 0x01],
    f32x4abs: [0xfd, 0xe0, 0x01], f32x4sqrt: [0xfd, 0xe3, 0x01],
    f32x4add: [0xfd, 0xe4, 0x01], f32x4sub: [0xfd, 0xe5, 0x01], f32x4mul: [0xfd, 0xe6, 0x01], f32x4div: [0xfd, 0xe7, 0x01],
    i8x16shuffle: (lanes) => [0xfd, 0x0d, ...lanes],
    f32x4relaxedMadd: [0xfd, 0x85, 0x02],
    i32x4relaxedTruncF32x4S: [0xfd, 0x81, 0x02]
};

// ---------------------------------------------------------------------------
// Capability probes: modules that only have to validate
// ---------------------------------------------------------------------------

const WASM_BASELINE = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
const VOID_FN = { params: [], results: [] };

const WASM_FEATURE_PROBES = {
    simd: wasmModule({ types: [VOID_FN], funcs: [{ type: 0, body: seq(W.i32(0), W.i32x4splat, W.drop) }] }),
    relaxedSimd: wasmModule({
        types: [VOID_FN],
        funcs: [{ type: 0, body: seq(W.v128([0, 0, 0, 0]), W.v128([0, 0, 0, 0]), W.v128([0, 0, 0, 0]), W.f32x4relaxedMadd, W.drop) }]
    }),
    // atomics on a shared memory: the instruction set part of WebAssembly threads
    threadsAtomics: wasmModule({
        types: [VOID_FN],
        memory: { min: 1, max: 1, shared: true },
        funcs: [{ type: 0, body: seq(W.i32(0), W.i32(1), [0xfe, 0x1e, 0x02, 0x00], W.drop) }] // i32.atomic.rmw.add
    }),
    bulkMemory: wasmModule({
        types: [VOID_FN],
        memory: { min: 1 },
        funcs: [{ type: 0, body: seq(W.i32(0), W.i32(0), W.i32(0), [0xfc, 0x0a, 0x00, 0x00]) }] // memory.copy
    }),
    referenceTypes: wasmModule({ types: [VOID_FN], funcs: [{ type: 0, body: seq([0xd0, 0x6f], W.drop) }] }), // ref.null extern
    multiValue: wasmModule({ types: [{ params: [], results: [WT.i32, WT.i32] }], funcs: [{ type: 0, body: seq(W.i32(0), W.i32(0)) }] }),
    signExtension: wasmModule({ types: [VOID_FN], funcs: [{ type: 0, body: seq(W.i32(0), [0xc0], W.drop) }] }), // i32.extend8_s
    saturatingFloatToInt: wasmModule({ types: [VOID_FN], funcs: [{ type: 0, body: seq(W.f32(0), [0xfc, 0x00], W.drop) }] }),
    tailCall: wasmModule({ types: [VOID_FN], funcs: [{ type: 0, body: seq([0x12, 0x00]) }] }), // return_call 0
    // legacy exception handling: try / catch_all
    exceptionHandling: wasmModule({ types: [VOID_FN], funcs: [{ type: 0, body: seq([0x06, 0x40, 0x19, 0x0b]) }] }),
    // fixed byte sequences from the feature-detection convention, kept literal:
    // data segment whose offset is an i32.add constant expression
    extendedConst: new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 5, 3, 1, 0, 1, 11, 9, 1, 0, 65, 1, 65, 2, 106, 11, 0]),
    // memory with the i64 index flag
    memory64: new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 5, 3, 1, 4, 1]),
    // two memories in one module
    multiMemory: new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 5, 5, 2, 0, 0, 0, 0]),
    // type section with a GC struct type
    gc: new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 95, 1, 120, 0])
};

// Atomic add on an imported shared memory, used by the thread execution probe
const WASM_THREAD_MODULE = wasmModule({
    types: [{ params: [WT.i32], results: [WT.i32] }],
    imports: [{ module: "env", name: "mem", memory: { min: 1, max: 1, shared: true } }],
    funcs: [{ type: 0, export: "inc", body: seq(W.get(0), W.i32(1), [0xfe, 0x1e, 0x02, 0x00]) }]
});

const WASM_WORKER_SOURCE = `
self.onmessage = async (event) => {
    try {
        const { memory, bytes, count } = event.data;
        const { instance } = await WebAssembly.instantiate(bytes, { env: { mem: memory } });
        for (let i = 0; i < count; i++) instance.exports.inc(0);
        self.postMessage({ done: true });
    } catch (e) {
        self.postMessage({ error: String(e) });
    }
};`;

function wasmValidates(bytes) {
    try { return WebAssembly.validate(bytes); } catch (e) { return false; }
}

// ---------------------------------------------------------------------------
// Computation programs. Each has a JavaScript reference implementation that must
// produce the same result: WebAssembly integer and IEEE-754 arithmetic is exact, so
// any mismatch means an engine bug or tampering, not noise.
// ---------------------------------------------------------------------------

// xorshift32 mixed with imul, rotate, popcnt/clz/ctz and signed/unsigned division
const WASM_PROGRAMS = {};
{
    // locals: 0 seed, 1 n (params); 2 x, 3 acc, 4 i, 5 d
    const loopBody = seq(
        W.get(4), W.get(1), W.i32geU, W.brIf(1),
        W.get(2), W.get(2), W.i32(13), W.i32shl, W.i32xor, W.set(2),
        W.get(2), W.get(2), W.i32(17), W.i32shrU, W.i32xor, W.set(2),
        W.get(2), W.get(2), W.i32(5), W.i32shl, W.i32xor, W.set(2),
        W.get(4), W.i32(1), W.i32or, W.set(5),
        W.get(3), W.get(2), W.i32(0x9e3779b1), W.i32mul, W.i32add, W.i32(5), W.i32rotl,
        W.get(2), W.i32popcnt, W.get(2), W.i32clz, W.i32add, W.get(2), W.i32ctz, W.i32add,
        W.get(2), W.get(5), W.i32divS, W.i32add, W.get(2), W.get(5), W.i32remU, W.i32add,
        W.i32xor, W.set(3),
        W.get(4), W.i32(1), W.i32add, W.set(4),
        W.br(0)
    );
    WASM_PROGRAMS.i32 = {
        type: { params: [WT.i32, WT.i32], results: [WT.i32] },
        locals: [[4, WT.i32]],
        body: seq(W.get(0), W.set(2), W.block, W.loop, loopBody, W.end, W.end, W.get(3))
    };
}
{
    // locals: 0 seed (i64), 1 n (i32); 2 x (i64), 3 acc (i64), 4 i (i32), 5 d (i64)
    const loopBody = seq(
        W.get(4), W.get(1), W.i32geU, W.brIf(1),
        W.get(2), W.get(2), W.i64(13), W.i64shl, W.i64xor, W.set(2),
        W.get(2), W.get(2), W.i64(7), W.i64shrU, W.i64xor, W.set(2),
        W.get(2), W.get(2), W.i64(17), W.i64shl, W.i64xor, W.set(2),
        W.get(4), W.i32(1), W.i32or, W.i64extendI32U, W.set(5),
        W.get(3), W.get(2), W.i64(0x9e3779b97f4a7c15n), W.i64mul, W.i64add, W.i64(11), W.i64rotl,
        W.get(2), W.i64popcnt, W.get(2), W.i64clz, W.i64add, W.get(2), W.i64ctz, W.i64add,
        W.get(2), W.get(5), W.i64divU, W.i64add, W.get(2), W.get(5), W.i64remS, W.i64add,
        W.i64xor, W.set(3),
        W.get(4), W.i32(1), W.i32add, W.set(4),
        W.br(0)
    );
    WASM_PROGRAMS.i64 = {
        type: { params: [WT.i64, WT.i32], results: [WT.i64] },
        locals: [[2, WT.i64], [1, WT.i32], [1, WT.i64]],
        body: seq(W.get(0), W.set(2), W.block, W.loop, loopBody, W.end, W.end, W.get(3))
    };
}
{
    // f64: locals 0 n (param); 1 i (i32); 2 x, 3 acc, 4 t (f64)
    const loopBody = seq(
        W.get(1), W.get(0), W.i32geU, W.brIf(1),
        W.get(1), W.f64convertI32U, W.f64(1.5), W.f64add, W.set(4),
        W.get(2), W.f64(1.0000001), W.f64mul, W.get(4), W.f64sqrt, W.get(4), W.f64(1.0), W.f64add, W.f64div, W.f64add, W.set(2),
        W.get(3),
        W.get(2), W.f64(3.7), W.f64mul, W.f64nearest, W.f64add,
        W.get(2), W.f64(1.3), W.f64mul, W.f64trunc, W.f64sub,
        W.get(2), W.f64ceil, W.f64(-1.0), W.f64copysign, W.f64(0.001), W.f64mul, W.f64add,
        W.get(2), W.f64(2.5), W.f64min, W.f64add,
        W.get(2), W.f64(0.25), W.f64max, W.f64(0.5), W.f64mul, W.f64sub,
        W.set(3),
        W.get(2), W.get(2), W.f64(3.0), W.f64div, W.f64floor, W.f64(3.0), W.f64mul, W.f64sub, W.set(2),
        W.get(1), W.i32(1), W.i32add, W.set(1),
        W.br(0)
    );
    WASM_PROGRAMS.f64 = {
        type: { params: [WT.i32], results: [WT.f64] },
        locals: [[1, WT.i32], [3, WT.f64]],
        body: seq(W.f64(1.0), W.set(2), W.block, W.loop, loopBody, W.end, W.end, W.get(3))
    };
}
{
    // f32: same shape as f64, every operation rounds to single precision
    const loopBody = seq(
        W.get(1), W.get(0), W.i32geU, W.brIf(1),
        W.get(1), W.f32convertI32U, W.f32(1.5), W.f32add, W.set(4),
        W.get(2), W.f32(1.0000001), W.f32mul, W.get(4), W.f32sqrt, W.get(4), W.f32(1.0), W.f32add, W.f32div, W.f32add, W.set(2),
        W.get(3),
        W.get(2), W.f32(3.7), W.f32mul, W.f32nearest, W.f32add,
        W.get(2), W.f32(1.3), W.f32mul, W.f32trunc, W.f32sub,
        W.get(2), W.f32ceil, W.f32(-1.0), W.f32copysign, W.f32(0.001), W.f32mul, W.f32add,
        W.get(2), W.f32(2.5), W.f32min, W.f32add,
        W.get(2), W.f32(0.25), W.f32max, W.f32(0.5), W.f32mul, W.f32sub,
        W.set(3),
        W.get(2), W.get(2), W.f32(3.0), W.f32div, W.f32floor, W.f32(3.0), W.f32mul, W.f32sub, W.set(2),
        W.get(1), W.i32(1), W.i32add, W.set(1),
        W.br(0)
    );
    WASM_PROGRAMS.f32 = {
        type: { params: [WT.i32], results: [WT.f32] },
        locals: [[1, WT.i32], [3, WT.f32]],
        body: seq(W.f32(1.0), W.set(2), W.block, W.loop, loopBody, W.end, W.end, W.get(3))
    };
}
// float -> int conversions with spec-defined saturation
WASM_PROGRAMS.satS = { type: { params: [WT.f64], results: [WT.i32] }, locals: [], body: seq(W.get(0), W.i32truncSatF64S) };
WASM_PROGRAMS.satU = { type: { params: [WT.f64], results: [WT.i32] }, locals: [], body: seq(W.get(0), W.i32truncSatF64U) };
WASM_PROGRAMS.truncTrap = { type: { params: [WT.f64], results: [WT.i32] }, locals: [], body: seq(W.get(0), W.i32truncF64S) };
{
    // SIMD integer lanes. locals: 0 n; 1 i (i32), 2 r (i32), 3 a (v128), 4 b (v128)
    const lanes = (v) => seq(
        W.get(v), W.i32x4extract(0),
        W.get(v), W.i32x4extract(1), W.i32(8), W.i32rotl, W.i32xor,
        W.get(v), W.i32x4extract(2), W.i32(16), W.i32rotl, W.i32xor,
        W.get(v), W.i32x4extract(3), W.i32(24), W.i32rotl, W.i32xor
    );
    const loopBody = seq(
        W.get(1), W.get(0), W.i32geU, W.brIf(1),
        // a = ((a * b) + (a << 7)) ^ (a >>> 11)
        W.get(3), W.get(4), W.i32x4mul, W.get(3), W.i32(7), W.i32x4shl, W.i32x4add,
        W.get(3), W.i32(11), W.i32x4shrU, W.v128xor, W.set(3),
        // b = bytes 4..15 of b followed by bytes 0..3 of the new a
        W.get(4), W.get(3), W.i8x16shuffle([4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]), W.set(4),
        W.get(1), W.i32(1), W.i32add, W.set(1),
        W.br(0)
    );
    WASM_PROGRAMS.simdInt = {
        type: { params: [WT.i32], results: [WT.i32] },
        locals: [[2, WT.i32], [2, WT.v128]],
        body: seq(
            W.v128([1, 2, 3, 4]), W.set(3),
            W.v128([0x9e3779b9, 0x85ebca6b, 0xc2b2ae35, 0x27d4eb2f]), W.set(4),
            W.block, W.loop, loopBody, W.end, W.end,
            lanes(3)
        )
    };
    // SIMD single-precision lanes. locals: 0 n; 1 i (i32); 2 v, 3 c1, 4 c2 (v128)
    const floatLoop = seq(
        W.get(1), W.get(0), W.i32geU, W.brIf(1),
        // v = sqrt(abs(v * c1 - c2)) + c2 / (v + 1)
        W.get(2), W.get(3), W.f32x4mul, W.get(4), W.f32x4sub, W.f32x4abs, W.f32x4sqrt,
        W.get(4), W.get(2), W.f32(1.0), W.f32x4splat, W.f32x4add, W.f32x4div, W.f32x4add, W.set(2),
        W.get(1), W.i32(1), W.i32add, W.set(1),
        W.br(0)
    );
    WASM_PROGRAMS.simdFloat = {
        type: { params: [WT.i32], results: [WT.i32] },
        locals: [[1, WT.i32], [3, WT.v128]],
        body: seq(
            // lane constants are written as raw f32 bit patterns
            W.v128([0x3f800000, 0x40000000, 0x40400000, 0x40800000]), W.set(2),
            W.v128(Array.from(new Uint32Array(new Float32Array([1.1, 0.9, 1.3, 0.7]).buffer))), W.set(3),
            W.v128(Array.from(new Uint32Array(new Float32Array([0.5, 1.5, 2.5, 3.5]).buffer))), W.set(4),
            W.block, W.loop, floatLoop, W.end, W.end,
            // lanes reinterpreted as integers and folded together
            W.get(2), W.i32x4extract(0),
            W.get(2), W.i32x4extract(1), W.i32(8), W.i32rotl, W.i32xor,
            W.get(2), W.i32x4extract(2), W.i32(16), W.i32rotl, W.i32xor,
            W.get(2), W.i32x4extract(3), W.i32(24), W.i32rotl, W.i32xor
        )
    };
}
// Values the specification leaves to the implementation
WASM_PROGRAMS.nanF64 = {
    type: { params: [WT.f64, WT.f64], results: [WT.i64] },
    locals: [],
    body: seq(W.get(0), W.get(1), W.f64div, W.i64reinterpretF64)
};
WASM_PROGRAMS.nanF32 = {
    type: { params: [WT.f32, WT.f32], results: [WT.i32] },
    locals: [],
    body: seq(W.get(0), W.get(1), W.f32div, W.i32reinterpretF32)
};
// relaxed_madd(a, b, c): fused or not, and the out-of-range result of relaxed truncation
WASM_PROGRAMS.relaxedMadd = {
    type: { params: [WT.f32, WT.f32, WT.f32], results: [WT.f32] },
    locals: [],
    body: seq(W.get(0), W.f32x4splat, W.get(1), W.f32x4splat, W.get(2), W.f32x4splat, W.f32x4relaxedMadd, W.f32x4extract(0))
};
WASM_PROGRAMS.relaxedTruncNaN = {
    type: { params: [WT.f32], results: [WT.i32] },
    locals: [],
    body: seq(W.get(0), W.f32x4splat, W.i32x4relaxedTruncF32x4S, W.i32x4extract(0))
};

function wasmInstantiateProgram(name, extraProgram) {
    const program = extraProgram || WASM_PROGRAMS[name];
    const bytes = wasmModule({
        types: [program.type],
        funcs: [{ type: 0, locals: program.locals, body: program.body, export: "run" }]
    });
    return new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports.run;
}

// JavaScript references ------------------------------------------------------

const popcnt32 = (x) => { x >>>= 0; let c = 0; while (x) { c += x & 1; x >>>= 1; } return c; };
const ctz32 = (x) => (x === 0 ? 32 : 31 - Math.clz32(x & -x));
const rotl32 = (x, n) => (x << n) | (x >>> (32 - n));

function refI32(seed, n) {
    let x = seed | 0, acc = 0;
    for (let i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
        const d = i | 1;
        const mixed = rotl32((acc + Math.imul(x, 0x9e3779b1)) | 0, 5);
        const bits = popcnt32(x) + Math.clz32(x) + ctz32(x);
        acc = mixed ^ ((((bits + ((x / d) | 0)) | 0) + ((x >>> 0) % d)) | 0);
    }
    return acc | 0;
}

function refI64(seed, n) {
    const M = (v) => BigInt.asUintN(64, v);
    const rotl64 = (v, k) => M((v << BigInt(k)) | (v >> BigInt(64 - k)));
    const popcnt64 = (v) => { let c = 0n; while (v) { c += v & 1n; v >>= 1n; } return c; };
    let x = M(BigInt(seed)), acc = 0n;
    for (let i = 0; i < n; i++) {
        x = M(x ^ (x << 13n)); x = M(x ^ (x >> 7n)); x = M(x ^ (x << 17n));
        const d = BigInt(i | 1);
        const mixed = rotl64(M(acc + M(x * 0x9e3779b97f4a7c15n)), 11);
        const clz = x === 0n ? 64n : BigInt(64 - x.toString(2).length);
        const ctz = x === 0n ? 64n : BigInt(x.toString(2).length - 1 - x.toString(2).lastIndexOf("1"));
        const bits = M(popcnt64(x) + clz + ctz);
        const sum = M(M(bits + x / d) + BigInt.asUintN(64, BigInt.asIntN(64, x) % d));
        acc = M(mixed ^ sum);
    }
    return BigInt.asIntN(64, acc);
}

const roundEven = (x) => {
    const r = Math.round(x);
    return Math.abs(x % 1) === 0.5 && r % 2 !== 0 ? r - 1 : r;
};
const copysign = (a, b) => (Object.is(b, -0) || b < 0 ? -Math.abs(a) : Math.abs(a));

function refFloat(n, f) {
    // f = identity for f64, Math.fround for f32: every operation rounds through f
    let x = f(1.0), acc = f(0);
    for (let i = 0; i < n; i++) {
        const t = f(f(i) + f(1.5));
        x = f(f(x * f(1.0000001)) + f(f(Math.sqrt(t)) / f(t + f(1.0))));
        acc = f(acc + f(roundEven(f(x * f(3.7)))));
        acc = f(acc - f(Math.trunc(f(x * f(1.3)))));
        acc = f(acc + f(f(copysign(Math.ceil(x), -1.0)) * f(0.001)));
        acc = f(acc + Math.min(x, f(2.5)));
        acc = f(acc - f(Math.max(x, f(0.25)) * f(0.5)));
        x = f(x - f(f(Math.floor(f(x / f(3.0)))) * f(3.0)));
    }
    return acc;
}

const refSatS = (x) => (Number.isNaN(x) ? 0 : x >= 2147483647 ? 2147483647 : x <= -2147483648 ? -2147483648 : Math.trunc(x));
const refSatU = (x) => (Number.isNaN(x) || x <= 0 ? 0 : x >= 4294967295 ? -1 : Math.trunc(x) | 0);

function refSimdInt(n) {
    let a = [1, 2, 3, 4];
    let b = [0x9e3779b9 | 0, 0x85ebca6b | 0, 0xc2b2ae35 | 0, 0x27d4eb2f | 0];
    for (let i = 0; i < n; i++) {
        a = a.map((v, k) => ((Math.imul(v, b[k]) + (v << 7)) ^ (v >>> 11)) | 0);
        b = [b[1], b[2], b[3], a[0]];
    }
    return (a[0] ^ rotl32(a[1], 8) ^ rotl32(a[2], 16) ^ rotl32(a[3], 24)) | 0;
}

function refSimdFloat(n) {
    const f = Math.fround;
    let v = [1, 2, 3, 4].map(f);
    const c1 = [1.1, 0.9, 1.3, 0.7].map(f);
    const c2 = [0.5, 1.5, 2.5, 3.5].map(f);
    for (let i = 0; i < n; i++) {
        v = v.map((x, k) => f(f(Math.sqrt(Math.abs(f(f(x * c1[k]) - c2[k])))) + f(c2[k] / f(x + 1))));
    }
    const bits = Array.from(new Int32Array(new Float32Array(v).buffer));
    return (bits[0] ^ rotl32(bits[1], 8) ^ rotl32(bits[2], 16) ^ rotl32(bits[3], 24)) | 0;
}

const hex32 = (v) => (v >>> 0).toString(16).padStart(8, "0");
const hex64 = (v) => BigInt.asUintN(64, BigInt(v)).toString(16).padStart(16, "0");

// ---------------------------------------------------------------------------
// Test: capabilities (static)
// ---------------------------------------------------------------------------

async function getWasmCapabilities() {
    if (typeof WebAssembly !== "object" || !WebAssembly) unsupported("WebAssembly is not defined");
    if (!wasmValidates(WASM_BASELINE)) unavailable("WebAssembly exists but cannot validate a module (blocked by policy or CSP?)");

    // Instruction-set features: does the engine validate a module that uses them?
    const features = {};
    for (const [name, bytes] of Object.entries(WASM_FEATURE_PROBES)) features[name] = wasmValidates(bytes);

    const api = {
        instantiateStreaming: typeof WebAssembly.instantiateStreaming === "function",
        compileStreaming: typeof WebAssembly.compileStreaming === "function",
        Global: typeof WebAssembly.Global === "function",
        Tag: typeof WebAssembly.Tag === "function",
        Exception: typeof WebAssembly.Exception === "function",
        JSTag: typeof WebAssembly.JSTag !== "undefined",
        bigIntIntegration: typeof BigInt === "function" && await runSub(async () => {
            const bytes = wasmModule({ types: [{ params: [WT.i64], results: [WT.i64] }], funcs: [{ type: 0, export: "id", body: W.get(0) }] });
            const id = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports.id;
            return { roundTrips: id(0x7fffffffffffffffn) === 0x7fffffffffffffffn };
        }).then((r) => r.status === "success" && r.roundTrips)
    };

    // Shared memory and threads are separate questions, answered separately:
    //   exposure      is SharedArrayBuffer defined, is the page cross-origin isolated
    //   memory        can a shared WebAssembly.Memory be created
    //   atomics       does the engine accept atomic instructions
    //   workers       can a shared memory actually be handed to a Worker and used there
    const sharedMemory = await runSub(async () => {
        const memory = new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true });
        return {
            created: true,
            bufferIsSharedArrayBuffer: typeof SharedArrayBuffer === "function" && memory.buffer instanceof SharedArrayBuffer
        };
    });

    const threads = {
        sharedArrayBufferDefined: typeof SharedArrayBuffer === "function",
        crossOriginIsolated: window.crossOriginIsolated ?? null,
        atomicsDefined: typeof Atomics === "object",
        workerDefined: typeof Worker === "function",
        atomicInstructionsValidate: features.threadsAtomics,
        sharedMemory,
        execution: await runSub(runWasmThreadExecution)
    };

    return {
        raw: { features, api, threads },
        normalized: {
            features,
            api,
            // status words and booleans only: crossOriginIsolated is a deployment choice, so it
            // is reported here but does not decide the hash on its own
            threads: {
                atomicsDefined: threads.atomicsDefined,
                atomicInstructionsValidate: threads.atomicInstructionsValidate,
                sharedMemoryStatus: sharedMemory.status,
                executionStatus: threads.execution.status
            }
        },
        notes: [
            "Feature flags say what the engine validates, not what the hardware does. A false flag can also mean the feature is behind a flag or disabled by policy.",
            "Thread execution needs SharedArrayBuffer, which browsers only expose to cross-origin isolated pages. Without COOP/COEP headers that is expected to be unavailable."
        ]
    };
}

async function runWasmThreadExecution() {
    if (typeof Worker !== "function") unsupported("Worker is not defined");
    if (typeof SharedArrayBuffer !== "function") unavailable("SharedArrayBuffer is not exposed (page is not cross-origin isolated)");
    if (typeof Atomics !== "object") unsupported("Atomics is not defined");

    const COUNT = 1000;
    const memory = new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true });
    const { instance } = await WebAssembly.instantiate(WASM_THREAD_MODULE, { env: { mem: memory } });

    const url = URL.createObjectURL(new Blob([WASM_WORKER_SOURCE], { type: "text/javascript" }));
    let worker = null;
    try {
        worker = new Worker(url);
        const done = new Promise((resolve, reject) => {
            worker.onmessage = (e) => (e.data && e.data.error ? reject(new Error(e.data.error)) : resolve());
            worker.onerror = (e) => reject(new Error(e.message || "worker error"));
        });
        worker.postMessage({ memory, bytes: WASM_THREAD_MODULE, count: COUNT });
        // The main thread increments the same counter while the worker does
        for (let i = 0; i < COUNT; i++) instance.exports.inc(0);
        await withTimeout(done, 4000, "thread worker");
        const total = Atomics.load(new Int32Array(memory.buffer), 0);
        // Atomic adds never get lost, whatever the interleaving, so the total is exact
        if (total !== COUNT * 2) throw new Error(`atomic counter ${total}, expected ${COUNT * 2}`);
        return { counter: total };
    } finally {
        if (worker) worker.terminate();
        URL.revokeObjectURL(url);
    }
}

// ---------------------------------------------------------------------------
// Test: deterministic computation (behavioral)
// ---------------------------------------------------------------------------

async function getWasmComputation() {
    if (typeof WebAssembly !== "object" || !WebAssembly) unsupported("WebAssembly is not defined");
    if (!wasmValidates(WASM_BASELINE)) unavailable("WebAssembly cannot validate a module");

    const out = { integer: {}, float: {}, simd: {}, implementationDefined: {} };
    const normalized = { integer: {}, float: {}, simd: {} };

    // --- integer arithmetic: i32 and i64 -------------------------------------
    out.integer.i32 = await runSub(async () => {
        const run = wasmInstantiateProgram("i32");
        const got = run(0x2545f491, 5000), want = refI32(0x2545f491, 5000);
        return { value: hex32(got), matchesReference: got === want };
    });
    out.integer.i64 = await runSub(async () => {
        if (typeof BigInt !== "function") unsupported("BigInt is not defined");
        const run = wasmInstantiateProgram("i64");
        const got = run(0x2545f4914f6cdd1dn, 3000), want = refI64(0x2545f4914f6cdd1dn, 3000);
        return { value: hex64(got), matchesReference: got === want };
    });

    // --- floating point: f64, f32, saturating conversion --------------------------
    out.float.f64 = await runSub(async () => {
        const got = wasmInstantiateProgram("f64")(4000), want = refFloat(4000, (v) => v);
        return { bits: hex64(new BigUint64Array(new Float64Array([got]).buffer)[0]), matchesReference: Object.is(got, want) };
    });
    out.float.f32 = await runSub(async () => {
        const got = wasmInstantiateProgram("f32")(4000), want = refFloat(4000, Math.fround);
        return { bits: hex32(new Uint32Array(new Float32Array([got]).buffer)[0]), matchesReference: Object.is(got, want) };
    });
    out.float.saturatingConversion = await runSub(async () => {
        if (!wasmValidates(WASM_FEATURE_PROBES.saturatingFloatToInt)) unsupported("saturating float-to-int not supported");
        const inputs = [0.5, -0.5, 2147483647.9, 2147483648, -2147483649, 1e20, -1e20, NaN, Infinity, -Infinity, 4294967295.5, 4294967296, -0.9];
        const s = wasmInstantiateProgram("satS"), u = wasmInstantiateProgram("satU");
        const signed = inputs.map((x) => s(x)), unsignedResults = inputs.map((x) => u(x));
        const matches = signed.every((v, i) => v === refSatS(inputs[i])) && unsignedResults.every((v, i) => v === refSatU(inputs[i]));
        return { signed, unsigned: unsignedResults, matchesReference: matches };
    });
    out.float.trapName = await runSub(async () => {
        // the trap itself is specified; only the message text differs per engine, so only the name is kept
        const trunc = wasmInstantiateProgram("truncTrap");
        let name = null;
        try { trunc(NaN); } catch (e) { name = e && e.name; }
        return { name };
    });

    // --- SIMD ---------------------------------------------------------------------
    const simdSupported = wasmValidates(WASM_FEATURE_PROBES.simd);
    out.simd.int = await runSub(async () => {
        if (!simdSupported) unsupported("SIMD not supported");
        const got = wasmInstantiateProgram("simdInt")(2000), want = refSimdInt(2000);
        return { value: hex32(got), matchesReference: got === want };
    });
    out.simd.float = await runSub(async () => {
        if (!simdSupported) unsupported("SIMD not supported");
        const got = wasmInstantiateProgram("simdFloat")(500), want = refSimdFloat(500);
        return { value: hex32(got), matchesReference: got === want };
    });

    // --- results the specification allows to vary ----------------------------------
    // NaN sign and payload, and relaxed SIMD, depend on the CPU and engine rather than
    // on the specification, so they are hashed apart from everything above.
    const impl = out.implementationDefined;
    impl.nanBits = await runSub(async () => {
        const f64 = wasmInstantiateProgram("nanF64")(0, 0);
        const f32 = wasmInstantiateProgram("nanF32")(0, 0);
        return { f64: hex64(f64), f32: hex32(f32) };
    });
    impl.relaxedSimd = await runSub(async () => {
        if (!wasmValidates(WASM_FEATURE_PROBES.relaxedSimd)) unsupported("relaxed SIMD not supported");
        const a = Math.fround(1 + 2 ** -12), c = Math.fround(-(1 + 2 ** -11));
        const madd = wasmInstantiateProgram("relaxedMadd")(a, a, c);
        const trunc = wasmInstantiateProgram("relaxedTruncNaN")(NaN);
        // madd is exactly 0 when the multiply and add round separately, 2^-24 when fused
        return { maddFused: madd !== 0, maddValue: madd, truncNaN: hex32(trunc) };
    });

    // Reference mismatches are failures: exact arithmetic must match
    const mismatches = [];
    for (const group of ["integer", "float", "simd"]) {
        for (const [name, r] of Object.entries(out[group])) {
            if (r.status === "success" && r.matchesReference === false) mismatches.push(`${group}.${name}`);
        }
    }
    const succeeded = ["integer", "float", "simd"].some((g) => Object.values(out[g]).some((r) => r.status === "success"));
    if (!succeeded) unavailable("no WebAssembly program could be instantiated");
    if (mismatches.length) throw new Error(`WebAssembly result differs from the JavaScript reference: ${mismatches.join(", ")}`);

    for (const group of ["integer", "float", "simd"]) {
        for (const [name, r] of Object.entries(out[group])) {
            const { status, reason, error, matchesReference, ...values } = r;
            normalized[group][name] = status === "success" ? values : { status };
        }
    }
    const implementationDefined = {};
    for (const [name, r] of Object.entries(impl)) {
        const { status, reason, error, ...values } = r;
        implementationDefined[name] = status === "success" ? values : { status };
    }

    return {
        raw: out,
        normalized,
        hashes: { implementationDefined },
        notes: [
            "normalized holds only results that WebAssembly defines exactly (integer and IEEE-754 arithmetic), each checked against a JavaScript reference. They are identical on every correct engine, so this hash separates 'works' from 'broken or blocked', not one browser from another.",
            "hashes.implementationDefined covers NaN bits and relaxed SIMD, which depend on the CPU and engine. It is the part that can vary between machines, and a difference is not proof of a different device."
        ]
    };
}

registerTest({ id: "wasmCapabilities", category: "static", groups: ["browserEngine"], run: getWasmCapabilities, timeoutMs: 12000 });
registerTest({ id: "wasmComputation", category: "behavioral", groups: ["browserEngine", "cpu"], run: getWasmComputation });
