// Browser environment, screen details, API availability, device probes and
// experimental behaviour tests (IndexedDB, Cache, compression, RegExp, Intl, Date).
// Loaded after fingerprint-lib.js, which provides the test harness and hashing.

// Reads one property and reports why it is missing: unsupported (not in this browser)
// or unavailable (present but reading it threw, for example under a privacy policy)
function readProperty(read) {
    try {
        const value = read();
        if (value === undefined) return { status: "unsupported", reason: "property is undefined" };
        return { status: "success", value };
    } catch (e) {
        return { status: "unavailable", reason: `reading threw ${(e && e.name) || "Error"}` };
    }
}

const valuesOf = (entries) => Object.fromEntries(Object.entries(entries).map(([k, v]) => [k, v.status === "success" ? v.value : null]));
const statusesOf = (entries) => Object.fromEntries(Object.entries(entries).map(([k, v]) => [k, v.status]));

// ---------------------------------------------------------------------------
// Hardware, privacy settings, storage
// ---------------------------------------------------------------------------

// Hardware-derived values. Browsers may cap or bucket both of them.
async function getHardwareEnvironment() {
    const entries = {
        deviceMemory: readProperty(() => navigator.deviceMemory),
        hardwareConcurrency: readProperty(() => navigator.hardwareConcurrency)
    };
    if (Object.values(entries).every((e) => e.status !== "success")) unsupported("neither property is available");
    return {
        raw: entries,
        normalized: valuesOf(entries),
        notes: ["deviceMemory is capped at 8 (GB) and bucketed to powers of two; hardwareConcurrency may be capped or spoofed by privacy modes. Missing deviceMemory is normal outside Chromium."]
    };
}

// Settings the user or an extension can change, so they are configuration, not hardware
async function getBrowserSettings() {
    const entries = {
        cookieEnabled: readProperty(() => navigator.cookieEnabled),
        doNotTrack: readProperty(() => navigator.doNotTrack ?? window.doNotTrack ?? navigator.msDoNotTrack ?? undefined),
        globalPrivacyControl: readProperty(() => navigator.globalPrivacyControl),
        pdfViewerEnabled: readProperty(() => navigator.pdfViewerEnabled)
    };
    return {
        raw: entries,
        normalized: { values: valuesOf(entries), statuses: statusesOf(entries) },
        notes: ["doNotTrack is a string ('1', '0') or null, depending on the browser. null means unset or not exposed."]
    };
}

// Storage. Quota is bucketed; usage and similar counters change with every visit and are
// recorded for reference only, never hashed.
async function getStorageEnvironment() {
    if (!navigator.storage) unsupported("navigator.storage is not defined");

    const raw = {};
    const normalized = {};

    raw.estimate = await runSub(async () => {
        if (typeof navigator.storage.estimate !== "function") unsupported("estimate() missing");
        const e = await navigator.storage.estimate();
        return { quota: e.quota ?? null, usage: e.usage ?? null, usageDetails: e.usageDetails ?? null };
    });
    raw.persisted = await runSub(async () => {
        if (typeof navigator.storage.persisted !== "function") unsupported("persisted() missing");
        return { value: await navigator.storage.persisted() };
    });
    raw.opfs = typeof navigator.storage.getDirectory === "function";

    // Quota grows with disk size in some browsers and is capped or tiny in private modes. Only the
    // power-of-two bucket is kept, so a few GB of difference does not change the hash.
    const quota = raw.estimate.status === "success" ? raw.estimate.quota : null;
    normalized.estimate = {
        status: raw.estimate.status,
        quotaLog2Bucket: typeof quota === "number" && quota > 0 ? Math.floor(Math.log2(quota)) : null
    };
    normalized.persisted = { status: raw.persisted.status, value: raw.persisted.status === "success" ? raw.persisted.value : null };
    normalized.opfs = raw.opfs;

    return {
        raw,
        normalized,
        notes: ["usage is volatile (it changes as sites store data) and is deliberately absent from normalized. persisted() reflects a grant the user or the browser made, so it can change."]
    };
}

// ---------------------------------------------------------------------------
// Screen details (opt-in: may show a permission prompt)
// ---------------------------------------------------------------------------

async function getScreenDetailsTest() {
    if (typeof window.getScreenDetails !== "function") unsupported("getScreenDetails() is not defined");

    // Chromium names the permission window-management; older builds used window-placement
    let permission = null;
    for (const name of ["window-management", "window-placement"]) {
        try { permission = (await navigator.permissions.query({ name })).state; break; } catch (e) { /* try the next name */ }
    }
    if (permission === "denied") unavailable("permission denied");

    let details;
    try {
        details = await withTimeout(window.getScreenDetails(), 15000, "getScreenDetails");
    } catch (e) {
        if (e && (e.name === "NotAllowedError" || e.name === "SecurityError")) unavailable(`blocked: ${e.name}`);
        throw e;
    }
    const describe = (s) => ({
        width: s.width, height: s.height, availWidth: s.availWidth, availHeight: s.availHeight,
        left: s.left ?? null, top: s.top ?? null,
        colorDepth: s.colorDepth, pixelDepth: s.pixelDepth, devicePixelRatio: s.devicePixelRatio,
        isPrimary: s.isPrimary ?? null, isInternal: s.isInternal ?? null, isExtended: s.isExtended ?? null,
        orientation: s.orientation ? s.orientation.type : null
    });
    const screens = Array.from(details.screens || [], (s) => ({ ...describe(s), label: s.label || null }));
    const current = details.currentScreen ? describe(details.currentScreen) : null;

    // Physical size of each screen: CSS size times pixel ratio, which stays the same under browser zoom
    const devicePixels = screens.map((s) => `${Math.round(s.width * s.devicePixelRatio)}x${Math.round(s.height * s.devicePixelRatio)}`);
    return {
        raw: { permissionBefore: permission, screenCount: screens.length, screens, currentScreen: current },
        normalized: {
            screenCount: screens.length,
            devicePixelsPerScreen: devicePixels.slice().sort(),
            internalCount: screens.filter((s) => s.isInternal === true).length,
            hasPrimary: screens.some((s) => s.isPrimary === true)
        },
        notes: ["Window positions (left/top) and labels are in raw only: they change when monitors are moved or renamed. Normalized keeps the count and zoom-independent pixel sizes."]
    };
}

// ---------------------------------------------------------------------------
// API availability (static) and device availability (configuration)
// ---------------------------------------------------------------------------

// Permissions-policy names that gate each API
const API_POLICY = { usb: "usb", bluetooth: "bluetooth", serial: "serial", hid: "hid", xr: "xr-spatial-tracking", camera: "camera", microphone: "microphone", accelerometer: "accelerometer", gyroscope: "gyroscope" };

function policyAllows(feature) {
    try {
        const policy = document.permissionsPolicy || document.featurePolicy;
        if (policy && typeof policy.allowsFeature === "function") return policy.allowsFeature(feature);
    } catch (e) { /* ignore */ }
    return null; // cannot tell
}

// Whether an API is present and usable here. Says nothing about whether any device exists.
function describeApi({ iface, instance, policy, secureOnly = true }) {
    const interfaceDefined = iface ? typeof window[iface] !== "undefined" : null;
    let instanceDefined;
    try { instanceDefined = instance(); } catch (e) { instanceDefined = false; }
    const policyAllowed = policy ? policyAllows(API_POLICY[policy]) : null;
    const exposed = !!(instanceDefined || interfaceDefined);
    let status = "success", reason = null;
    if (!exposed) { status = "unsupported"; reason = "not exposed by this browser"; }
    else if (secureOnly && !window.isSecureContext) { status = "unavailable"; reason = "needs a secure context"; }
    else if (policyAllowed === false) { status = "unavailable"; reason = "blocked by permissions policy"; }
    return { status, reason, interfaceDefined, instanceDefined: !!instanceDefined, policyAllowed };
}

async function getApiAvailability() {
    const md = navigator.mediaDevices;
    const apis = {
        webUsb: describeApi({ iface: "USB", instance: () => "usb" in navigator, policy: "usb" }),
        webBluetooth: describeApi({ iface: "Bluetooth", instance: () => "bluetooth" in navigator, policy: "bluetooth" }),
        webSerial: describeApi({ iface: "Serial", instance: () => "serial" in navigator, policy: "serial" }),
        webHid: describeApi({ iface: "HID", instance: () => "hid" in navigator, policy: "hid" }),
        webXr: describeApi({ iface: "XRSystem", instance: () => "xr" in navigator, policy: "xr" }),
        mediaDevices: {
            ...describeApi({ iface: "MediaDevices", instance: () => !!md }),
            members: {
                getUserMedia: !!(md && md.getUserMedia), getDisplayMedia: !!(md && md.getDisplayMedia),
                enumerateDevices: !!(md && md.enumerateDevices), getSupportedConstraints: !!(md && md.getSupportedConstraints)
            }
        },
        deviceOrientation: {
            ...describeApi({ iface: "DeviceOrientationEvent", instance: () => typeof DeviceOrientationEvent !== "undefined", policy: "gyroscope", secureOnly: false }),
            // iOS-style: events only arrive after an explicit user-gesture permission request
            requiresPermissionRequest: typeof window.DeviceOrientationEvent !== "undefined" && typeof DeviceOrientationEvent.requestPermission === "function"
        },
        deviceMotion: {
            ...describeApi({ iface: "DeviceMotionEvent", instance: () => typeof DeviceMotionEvent !== "undefined", policy: "accelerometer", secureOnly: false }),
            requiresPermissionRequest: typeof window.DeviceMotionEvent !== "undefined" && typeof DeviceMotionEvent.requestPermission === "function"
        },
        sharedArrayBuffer: (() => {
            const defined = typeof SharedArrayBuffer === "function";
            let constructible = false;
            if (defined) { try { constructible = !!new SharedArrayBuffer(1); } catch (e) { constructible = false; } }
            return {
                status: defined ? (constructible ? "success" : "unavailable") : "unsupported",
                reason: defined ? (constructible ? null : "constructor throws") : "not exposed (not defined, or the page is not cross-origin isolated)",
                interfaceDefined: defined, constructible
            };
        })(),
        crossOriginIsolated: {
            status: typeof window.crossOriginIsolated === "boolean" ? "success" : "unsupported",
            value: typeof window.crossOriginIsolated === "boolean" ? window.crossOriginIsolated : null
        }
    };
    return {
        raw: { isSecureContext: window.isSecureContext, apis },
        normalized: Object.fromEntries(Object.entries(apis).map(([name, a]) => [name, { status: a.status, ...(a.value !== undefined ? { value: a.value } : {}) }])),
        notes: [
            "success means the API is exposed and usable here. It does not mean any device exists: see deviceAvailability.",
            "unavailable means the API exists but this page cannot use it (insecure context or permissions policy). It is a property of the page, not of the browser build."
        ]
    };
}

// Listens briefly for a sensor event. Reports whether an event arrived and whether it carried data.
// Desktop browsers often fire one event with all values null, which is not a sensor.
function probeSensorEvent(eventName, hasData, ms = 400) {
    return new Promise((resolve) => {
        let fired = false, data = false;
        const handler = (e) => { fired = true; try { data = data || !!hasData(e); } catch (err) { /* ignore */ } };
        window.addEventListener(eventName, handler);
        setTimeout(() => {
            window.removeEventListener(eventName, handler);
            resolve({ eventFired: fired, hasSensorData: data });
        }, ms);
    });
}

// Only calls that never show a prompt. Counts of devices the user already granted access to
// reflect past choices, which is why this is configuration.
async function getDeviceAvailability({ result }) {
    const probes = {};

    probes.usb = await runSub(async () => {
        if (!("usb" in navigator)) unsupported("navigator.usb missing");
        return { permittedDevices: (await navigator.usb.getDevices()).length };
    });
    probes.serial = await runSub(async () => {
        if (!("serial" in navigator)) unsupported("navigator.serial missing");
        return { permittedPorts: (await navigator.serial.getPorts()).length };
    });
    probes.hid = await runSub(async () => {
        if (!("hid" in navigator)) unsupported("navigator.hid missing");
        return { permittedDevices: (await navigator.hid.getDevices()).length };
    });
    probes.bluetooth = await runSub(async () => {
        if (!("bluetooth" in navigator)) unsupported("navigator.bluetooth missing");
        if (typeof navigator.bluetooth.getAvailability !== "function") unavailable("getAvailability() missing");
        return { adapterAvailable: await navigator.bluetooth.getAvailability() };
    });
    probes.xr = await runSub(async () => {
        if (!("xr" in navigator)) unsupported("navigator.xr missing");
        const modes = {};
        for (const mode of ["inline", "immersive-vr", "immersive-ar"]) {
            try { modes[mode] = !!(await withTimeout(navigator.xr.isSessionSupported(mode), 3000, "isSessionSupported")); }
            catch (e) { modes[mode] = null; }
        }
        return { sessionModes: modes };
    });
    probes.mediaDevices = await runSub(async () => {
        const known = result && result.mediaDevices && result.mediaDevices.counts;
        if (known) return { deviceKindCounts: known };
        if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) unsupported("enumerateDevices missing");
        const counts = {};
        (await navigator.mediaDevices.enumerateDevices()).forEach((d) => { counts[d.kind] = (counts[d.kind] || 0) + 1; });
        return { deviceKindCounts: counts };
    });
    probes.deviceOrientation = await runSub(async () => {
        if (typeof DeviceOrientationEvent === "undefined") unsupported("DeviceOrientationEvent missing");
        // On iOS, calling requestPermission() would prompt, and without it no events arrive
        if (typeof DeviceOrientationEvent.requestPermission === "function") unavailable("permission request required (not requested)");
        return probeSensorEvent("deviceorientation", (e) => e.alpha !== null || e.beta !== null || e.gamma !== null);
    });
    probes.deviceMotion = await runSub(async () => {
        if (typeof DeviceMotionEvent === "undefined") unsupported("DeviceMotionEvent missing");
        if (typeof DeviceMotionEvent.requestPermission === "function") unavailable("permission request required (not requested)");
        return probeSensorEvent("devicemotion", (e) => {
            const a = e.accelerationIncludingGravity, r = e.rotationRate;
            return !!((a && (a.x !== null || a.y !== null || a.z !== null)) || (r && (r.alpha !== null || r.beta !== null || r.gamma !== null)));
        });
    });

    const normalized = {};
    for (const [name, p] of Object.entries(probes)) {
        const { status, reason, error, ...values } = p;
        normalized[name] = status === "success" ? values : { status };
    }
    if (Object.values(probes).every((p) => p.status === "unsupported")) unsupported("no probed API exists");
    return {
        raw: probes,
        normalized,
        notes: ["Counts for usb, serial and hid are devices this origin was already granted; nothing is requested. bluetooth reports whether an adapter exists, not whether any device is nearby.", "Sensor probes only note whether event data arrived. The sensor values themselves are never stored."]
    };
}

// ---------------------------------------------------------------------------
// Experimental behaviour tests
// ---------------------------------------------------------------------------

function fpRandomName(prefix) {
    return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

// IndexedDB: does it work at all (private modes often break it), and which value types survive a round trip
async function getIndexedDbBehavior() {
    if (typeof indexedDB === "undefined") unsupported("indexedDB is not defined");

    const name = fpRandomName("fp_idb");
    let db = null;
    try {
        db = await withTimeout(new Promise((resolve, reject) => {
            const req = indexedDB.open(name, 1);
            req.onupgradeneeded = () => req.result.createObjectStore("s");
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error || new Error("open failed"));
            req.onblocked = () => reject(new Error("open blocked"));
        }), 5000, "indexedDB.open");
    } catch (e) {
        // Firefox private browsing and locked-down profiles reject here: the API exists but cannot be used
        if (/timed out/.test(String(e && e.message))) throw e;
        unavailable(`open failed: ${(e && e.name) || "Error"}`);
    }

    try {
        const tx = (mode) => db.transaction("s", mode).objectStore("s");
        const request = (r) => new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
        const roundTrip = async (label, value, check) => {
            try {
                await request(tx("readwrite").put(value, label));
                const back = await request(tx("readonly").get(label));
                return check(back) ? "preserved" : "altered";
            } catch (e) {
                return `rejected:${(e && e.name) || "Error"}`;
            }
        };

        const values = {
            number: await roundTrip("n", 1.5, (v) => v === 1.5),
            bigint: typeof BigInt === "function" ? await roundTrip("b", 123n, (v) => v === 123n) : "unsupported",
            date: await roundTrip("d", new Date(0), (v) => v instanceof Date && v.getTime() === 0),
            map: await roundTrip("m", new Map([[1, 2]]), (v) => v instanceof Map && v.get(1) === 2),
            set: await roundTrip("s", new Set([1]), (v) => v instanceof Set && v.has(1)),
            regexp: await roundTrip("r", /a+/gi, (v) => v instanceof RegExp && v.flags === "gi"),
            typedArray: await roundTrip("t", new Uint8Array([1, 2, 3]), (v) => v instanceof Uint8Array && v.length === 3),
            arrayBuffer: await roundTrip("ab", new ArrayBuffer(4), (v) => v instanceof ArrayBuffer && v.byteLength === 4),
            blob: typeof Blob === "function" ? await roundTrip("bl", new Blob(["x"]), (v) => v instanceof Blob && v.size === 1) : "unsupported",
            error: await roundTrip("e", new RangeError("x"), (v) => v instanceof Error && v.name === "RangeError"),
            nestedCycle: await roundTrip("c", (() => { const o = {}; o.self = o; return o; })(), (v) => v && v.self === v)
        };

        // Which key types are legal. Binary keys and array keys are optional in older engines.
        const keyType = (key) => { try { indexedDB.cmp(key, key); return true; } catch (e) { return false; } };
        const keys = {
            array: keyType([1, "a"]),
            date: keyType(new Date(0)),
            arrayBuffer: keyType(new ArrayBuffer(1)),
            typedArray: keyType(new Uint8Array(1)),
            // total order of mixed keys: number < date < string < binary < array
            order: (() => { try { return [indexedDB.cmp(1, new Date(0)), indexedDB.cmp("a", 1), indexedDB.cmp([], "a"), indexedDB.cmp(new ArrayBuffer(1), "a")].join(","); } catch (e) { return null; } })()
        };

        const api = {
            databases: typeof indexedDB.databases === "function",
            durabilityOption: await (async () => { try { db.transaction("s", "readonly", { durability: "relaxed" }); return true; } catch (e) { return false; } })(),
            getAllRecords: typeof IDBObjectStore.prototype.getAllRecords === "function",
            getAllKeys: typeof IDBObjectStore.prototype.getAllKeys === "function",
            IDBObjectStoreCount: typeof IDBObjectStore.prototype.count === "function"
        };
        return {
            raw: { values, keys, api },
            normalized: { values, keys, api },
            notes: ["Uses one temporary database that is deleted afterwards. No timing is recorded. 'rejected' values often mean private browsing or a storage policy rather than an old browser."]
        };
    } finally {
        try { db.close(); } catch (e) { /* ignore */ }
        try { indexedDB.deleteDatabase(name); } catch (e) { /* ignore */ }
    }
}

// Cache API: availability (also differs in private modes) and basic Response semantics
async function getCacheApiBehavior() {
    if (typeof caches === "undefined") {
        unsupported(window.isSecureContext ? "caches is not defined" : "caches needs a secure context");
    }
    const name = fpRandomName("fp_cache");
    let cache = null;
    try {
        cache = await withTimeout(caches.open(name), 5000, "caches.open");
        const url = `/__fp_cache_probe__/${name}`;
        const out = {};
        await cache.put(url, new Response("probe", { headers: { "Content-Type": "text/plain", Vary: "Accept-Language" } }));
        const hit = await cache.match(url, { headers: { "Accept-Language": "en" } });
        out.putAndMatch = !!hit;
        out.bodyRoundTrip = hit ? (await hit.text()) === "probe" : null;
        // Vary handling: a different Accept-Language must miss unless ignoreVary is set
        out.varyRespected = !(await cache.match(new Request(url, { headers: { "Accept-Language": "de" } })));
        out.ignoreVaryHit = !!(await cache.match(new Request(url, { headers: { "Accept-Language": "de" } }), { ignoreVary: true }));
        out.keysIncludeRequest = (await cache.keys()).length === 1;
        out.deleteEntry = await cache.delete(url);
        out.methods = { addAll: typeof cache.addAll === "function", matchAll: typeof cache.matchAll === "function" };
        return { raw: out, normalized: out, notes: ["Creates one temporary cache and deletes it. Only booleans are stored."] };
    } finally {
        try { await caches.delete(name); } catch (e) { /* ignore */ }
    }
}

// Compression: which formats exist, and the exact bytes this engine's compressor produces.
// Different zlib builds and settings give different (equally valid) output for the same input.
async function getCompressionBehavior() {
    if (typeof CompressionStream === "undefined") unsupported("CompressionStream is not defined");

    // Fixed pseudo-random text-like input from a linear congruential generator
    const words = ["alpha", "beta", "gamma", "delta", "ზღვა", "мир", "fingerprint", "stream"];
    let state = 12345, text = "";
    while (text.length < 24000) { state = (Math.imul(state, 1103515245) + 12345) >>> 0; text += words[(state >>> 16) % words.length] + (state & 8 ? " " : "\n"); }
    const input = new TextEncoder().encode(text);

    const run = async (stream, data) => {
        const writer = stream.writable.getWriter();
        writer.write(data).catch(() => {});
        writer.close().catch(() => {});
        return new Uint8Array(await new Response(stream.readable).arrayBuffer());
    };
    const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

    const formats = {};
    for (const format of ["gzip", "deflate", "deflate-raw", "deflate64", "brotli", "zstd"]) {
        formats[format] = await runSub(async () => {
            let compressor;
            try { compressor = new CompressionStream(format); } catch (e) { unsupported(`format not accepted (${e && e.name})`); }
            const packed = await run(compressor, input);
            let roundTrips = null;
            if (typeof DecompressionStream !== "undefined") {
                const unpacked = await run(new DecompressionStream(format), packed);
                roundTrips = unpacked.length === input.length && unpacked.every((b, i) => b === input[i]);
            }
            return {
                inputBytes: input.length,
                outputBytes: packed.length,
                headerHex: hex(packed.subarray(0, 10)),
                outputSha256: (await hashBytes(packed)).value,
                roundTrips
            };
        });
    }
    const supportedFormats = Object.keys(formats).filter((f) => formats[f].status === "success");
    if (!supportedFormats.length) unavailable("no compression format produced output");
    if (supportedFormats.some((f) => formats[f].roundTrips === false)) throw new Error("decompression did not restore the input");

    const normalized = {};
    for (const [f, r] of Object.entries(formats)) {
        const { status, reason, error, ...values } = r;
        normalized[f] = status === "success" ? { outputBytes: values.outputBytes, headerHex: values.headerHex, outputSha256: values.outputSha256 } : { status };
    }
    return {
        raw: { formats },
        normalized,
        notes: ["Output bytes depend on the compression library and its settings, so a different hash can come from a browser update. The gzip header's operating-system byte is part of headerHex."]
    };
}

// RegExp: feature support, case-folding and error text. Pure and deterministic.
async function getRegexpBehavior() {
    if (typeof RegExp !== "function") unsupported("RegExp is not defined");
    const attempt = (fn) => { try { return fn(); } catch (e) { return `error:${(e && e.name) || "Error"}`; } };
    const re = (source, flags) => new RegExp(source, flags);

    const features = {
        lookbehind: attempt(() => re("(?<=a)b").test("ab")),
        namedGroups: attempt(() => re("(?<y>\\d+)").exec("42").groups.y === "42"),
        unicodePropertyEscapes: attempt(() => re("\\p{Script=Georgian}", "u").test("ა")),
        vFlagSetOperations: attempt(() => re("[\\p{L}--[a-z]]", "v").test("A") && !re("[\\p{L}--[a-z]]", "v").test("a")),
        indicesFlag: attempt(() => Array.isArray(re("a(b)", "d").exec("ab").indices)),
        dotAllFlag: attempt(() => re("a.b", "s").test("a\nb")),
        stickyFlag: attempt(() => { const r = re("a", "y"); r.lastIndex = 1; return r.test("ba"); }),
        modifiers: attempt(() => re("(?i:a)b").test("Ab")),
        duplicateNamedGroups: attempt(() => re("(?<n>a)|(?<n>b)").exec("b").groups.n === "b"),
        regExpEscape: typeof RegExp.escape === "function",
        legacyStatics: attempt(() => { re("(x)").exec("x"); return RegExp.$1 === "x"; }),
        matchIndicesOnString: attempt(() => typeof "".matchAll === "function")
    };
    const behaviors = {
        // Kelvin sign and long s fold to k and s only under the u flag with i
        kelvinCaseFoldNoU: attempt(() => re("k", "i").test("\u212a")),
        kelvinCaseFoldU: attempt(() => re("k", "iu").test("\u212a")),
        dotlessIFold: attempt(() => re("\u0131", "i").test("I")),
        wordCharUnicodeIgnoreCase: attempt(() => re("\\w", "iu").test("\u017f")),
        surrogatePairNoU: attempt(() => re("^.$").test("😀")),
        surrogatePairU: attempt(() => re("^.$", "u").test("😀")),
        unmatchedGroup: attempt(() => String(re("(a)|b").exec("b")[1])),
        backreferenceToUnmatched: attempt(() => re("(a)?\\1b").test("b")),
        flagsOrder: attempt(() => re("a", "ysmigud").flags),
        replaceDollarForms: attempt(() => "abc".replace(re("(b)", "g"), "[$&|$1|$`|$']")),
        lastIndexAfterFailedGlobal: attempt(() => { const r = re("z", "g"); r.lastIndex = 2; r.test("abc"); return r.lastIndex; }),
        splitWithCaptures: attempt(() => "a1b2c".split(re("(\\d)")).join(",")),
        classEscapeInUnicodeMode: attempt(() => { try { re("[\\-]", "u"); return "ok"; } catch (e) { return "syntax"; } })
    };
    // The text of syntax errors differs between engines and versions
    const errors = {};
    for (const [label, src, flags] of [["unterminatedGroup", "(", ""], ["unterminatedClass", "[", ""], ["badQuantifier", "a{2,1}", ""], ["lonePlus", "+", ""], ["badEscapeU", "\\p{Nope}", "u"], ["badFlag", "a", "q"], ["badGroupName", "(?<1>a)", ""]]) {
        errors[label] = (() => { try { re(src, flags); return null; } catch (e) { return `${e.name}: ${e.message}`; } })();
    }
    return {
        raw: { features, behaviors, errors },
        normalized: { features, behaviors, errors },
        notes: ["Everything here is computed on fixed inputs, so results are the same on every visit unless the browser changes. Error text is engine-specific and can change between versions."]
    };
}

// Fixed instant used by the Intl tests: 2024-03-05 13:07:09 UTC
const FP_INTL_INSTANT = Date.UTC(2024, 2, 5, 13, 7, 9);

// Intl output for fixed locales and options. It depends on the engine's ICU/CLDR data, not on the user's
// settings, so it describes the browser build and is static.
async function getIntlData() {
    if (typeof Intl !== "object") unsupported("Intl is not defined");
    const attempt = (fn) => { try { return fn(); } catch (e) { return `error:${(e && e.name) || "Error"}`; } };
    const locales = ["en-US", "de-DE", "ka-GE", "ru-RU", "ar-EG", "ja-JP", "hi-IN", "th-TH"];
    const out = {};

    out.dateTime = Object.fromEntries(locales.map((l) => [l, attempt(() => new Intl.DateTimeFormat(l, { dateStyle: "full", timeStyle: "long", timeZone: "UTC" }).format(FP_INTL_INSTANT))]));
    out.dateParts = Object.fromEntries(["en-US", "ka-GE", "ja-JP"].map((l) => [l, attempt(() => new Intl.DateTimeFormat(l, { year: "numeric", month: "long", day: "numeric", weekday: "long", timeZone: "UTC" }).formatToParts(FP_INTL_INSTANT).map((p) => p.type).join(","))]));
    out.timeZoneNames = Object.fromEntries(["America/New_York", "Asia/Tbilisi", "Europe/Moscow", "Asia/Kolkata"].map((z) => [z, attempt(() => new Intl.DateTimeFormat("en-US", { timeZone: z, timeZoneName: "long" }).format(FP_INTL_INSTANT))]));
    out.number = Object.fromEntries(locales.map((l) => [l, attempt(() => new Intl.NumberFormat(l).format(1234567.891))]));
    out.currency = Object.fromEntries([["en-US", "USD"], ["ka-GE", "GEL"], ["de-DE", "EUR"], ["ja-JP", "JPY"]].map(([l, c]) => [`${l}/${c}`, attempt(() => new Intl.NumberFormat(l, { style: "currency", currency: c }).format(1234.5))]));
    out.compact = Object.fromEntries(["en-US", "ru-RU", "ja-JP"].map((l) => [l, attempt(() => new Intl.NumberFormat(l, { notation: "compact", compactDisplay: "long" }).format(1234567))]));
    out.unit = attempt(() => new Intl.NumberFormat("en-US", { style: "unit", unit: "kilometer-per-hour", unitDisplay: "narrow" }).format(88));
    out.plural = Object.fromEntries(["en", "ru", "ar", "ka"].map((l) => [l, attempt(() => [0, 1, 2, 3, 5, 11, 21, 100].map((n) => new Intl.PluralRules(l).select(n)).join(","))]));
    out.ordinal = attempt(() => [1, 2, 3, 4, 11].map((n) => new Intl.PluralRules("en", { type: "ordinal" }).select(n)).join(","));
    out.relativeTime = Object.fromEntries(["en", "ru", "ka"].map((l) => [l, attempt(() => new Intl.RelativeTimeFormat(l, { numeric: "auto" }).format(-1, "day") + "|" + new Intl.RelativeTimeFormat(l).format(3, "quarter"))]));
    out.list = Object.fromEntries(["en", "ka", "de"].map((l) => [l, attempt(() => new Intl.ListFormat(l, { type: "conjunction" }).format(["a", "b", "c"]))]));
    out.displayNames = attempt(() => ({
        region: new Intl.DisplayNames("en", { type: "region" }).of("GE"),
        language: new Intl.DisplayNames("en", { type: "language" }).of("ka"),
        script: new Intl.DisplayNames("en", { type: "script" }).of("Geor"),
        regionInGeorgian: new Intl.DisplayNames("ka", { type: "region" }).of("GE")
    }));
    out.collation = Object.fromEntries(["en", "de", "sv", "ka", "tr"].map((l) => [l, attempt(() => ["z", "ä", "a", "ö", "ç", "c", "i", "ı", "İ", "ა", "ბ"].sort(new Intl.Collator(l).compare).join(""))]));
    out.segmenter = attempt(() => typeof Intl.Segmenter === "function"
        ? Array.from(new Intl.Segmenter("en", { granularity: "grapheme" }).segment("🧑‍🚀🏳️‍🌈👍🏽e\u0301🫨")).length
        : "unsupported");
    out.supportedValues = attempt(() => {
        if (typeof Intl.supportedValuesOf !== "function") return "unsupported";
        const o = {};
        for (const key of ["calendar", "collation", "currency", "numberingSystem", "unit"]) o[key] = Intl.supportedValuesOf(key).length;
        // time zone identifiers: count only (the list itself varies with tzdata and is also a locale signal)
        o.timeZone = Intl.supportedValuesOf("timeZone").length;
        return o;
    });
    out.canonicalLocales = attempt(() => Intl.getCanonicalLocales(["EN-us", "ka-ge", "iw", "sr-latn-rs"]).join(","));

    return {
        raw: out,
        normalized: out,
        notes: ["All formatting uses explicit locales and a fixed instant, so the output reflects the browser's bundled locale data (ICU/CLDR), not the user's settings. Settings are in localeSettings."]
    };
}

// What the user's own locale settings produce. Configuration, because the user can change them.
async function getLocaleSettings() {
    if (typeof Intl !== "object") unsupported("Intl is not defined");
    const attempt = (fn) => { try { return fn(); } catch (e) { return `error:${(e && e.name) || "Error"}`; } };
    const dtf = Intl.DateTimeFormat().resolvedOptions();
    const out = {
        languages: Array.from(navigator.languages || []),
        language: navigator.language ?? null,
        resolved: { locale: dtf.locale, calendar: dtf.calendar, numberingSystem: dtf.numberingSystem, hourCycle: dtf.hourCycle ?? null, timeZone: dtf.timeZone },
        // fixed instant formatted with the default locale
        defaultDateTime: attempt(() => new Intl.DateTimeFormat(undefined, { dateStyle: "full", timeStyle: "long", timeZone: "UTC" }).format(FP_INTL_INSTANT)),
        defaultNumber: attempt(() => new Intl.NumberFormat().format(1234567.891)),
        defaultDatePartOrder: attempt(() => new Intl.DateTimeFormat(undefined, { year: "numeric", month: "numeric", day: "numeric", timeZone: "UTC" }).formatToParts(FP_INTL_INSTANT).map((p) => p.type === "literal" ? p.value : p.type).join("")),
        decimalSeparator: attempt(() => new Intl.NumberFormat().formatToParts(1.5).find((p) => p.type === "decimal").value),
        groupSeparator: attempt(() => new Intl.NumberFormat().formatToParts(1234567).find((p) => p.type === "group").value),
        weekInfo: attempt(() => { const l = new Intl.Locale(dtf.locale); const w = typeof l.getWeekInfo === "function" ? l.getWeekInfo() : l.weekInfo; return w ? { firstDay: w.firstDay, minimalDays: w.minimalDays } : null; }),
        toLocaleString: attempt(() => new Date(FP_INTL_INSTANT).toLocaleString(undefined, { timeZone: "UTC" })),
        collationOrder: attempt(() => ["z", "ä", "a", "ა", "я"].sort(new Intl.Collator().compare).join(""))
    };
    return {
        raw: out,
        normalized: out,
        notes: ["Language lists and locale formatting can differ from the request's Accept-Language header: see consistency."]
    };
}

// Date and time zone: offsets at fixed past, present and future instants, this year's transitions,
// Intl-versus-Date agreement, and parsing behaviour.
async function getTimezoneBehavior() {
    const attempt = (fn) => { try { return fn(); } catch (e) { return `error:${(e && e.name) || "Error"}`; } };
    const zone = attempt(() => Intl.DateTimeFormat().resolvedOptions().timeZone);

    const instants = {
        "1900-01-01": Date.UTC(1900, 0, 1), "1970-01-01": 0, "1990-07-01": Date.UTC(1990, 6, 1),
        "2000-01-01": Date.UTC(2000, 0, 1), "2010-07-01": Date.UTC(2010, 6, 1), "2020-01-01": Date.UTC(2020, 0, 1),
        "2026-01-15": Date.UTC(2026, 0, 15), "2026-07-15": Date.UTC(2026, 6, 15), "2035-07-01": Date.UTC(2035, 6, 1)
    };
    // Offsets in minutes (positive = east of UTC), from the Date object
    const dateOffsets = Object.fromEntries(Object.entries(instants).map(([k, t]) => [k, -new Date(t).getTimezoneOffset()]));

    // The same offsets worked out through Intl for the reported zone. A mismatch means one of the two
    // was altered (a spoofed zone name, or a patched Date).
    const intlOffset = (t) => attempt(() => {
        const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: zone, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric" })
            .formatToParts(t).filter((x) => x.type !== "literal").map((x) => [x.type, Number(x.value)]));
        return Math.round((Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - t) / 60000);
    });
    const intlOffsets = Object.fromEntries(Object.entries(instants).map(([k, t]) => [k, intlOffset(t)]));
    const disagreements = Object.keys(instants).filter((k) => typeof intlOffsets[k] === "number" && intlOffsets[k] !== dateOffsets[k]);

    // Days in 2026 on which the offset changes (daylight-saving transitions), with the size of the change
    const transitions = [];
    let previous = -new Date(Date.UTC(2026, 0, 1, 12)).getTimezoneOffset();
    for (let day = 1; day <= 365; day++) {
        const t = Date.UTC(2026, 0, 1 + day, 12);
        const now = -new Date(t).getTimezoneOffset();
        if (now !== previous) transitions.push(`${new Date(t).toISOString().slice(0, 10)}:${now - previous}`);
        previous = now;
    }

    const parsing = {
        isoDateOnly: Date.parse("2000-01-01"),               // UTC by specification
        isoDateTimeNoZone: Date.parse("2000-01-01T00:00"),     // local time by specification
        slashDate: Date.parse("2000/01/01 00:00"),
        nonPaddedIso: Date.parse("2000-1-1"),
        monthName: Date.parse("Jan 1 2000"),
        rfc: Date.parse("Sat, 01 Jan 2000 00:00:00 GMT"),
        twoDigitYear: Date.parse("1/1/49"),
        trailingGarbage: Date.parse("2000-01-01 foo")
    };
    const formats = {
        toStringPattern: String(new Date(0)).replace(/\d/g, "9"),
        toTimeStringPattern: new Date(0).toTimeString().replace(/\d/g, "9"),
        longNameEn: attempt(() => new Intl.DateTimeFormat("en-US", { timeZoneName: "long", timeZone: zone }).format(Date.UTC(2026, 0, 15))),
        shortNameEn: attempt(() => new Intl.DateTimeFormat("en-US", { timeZoneName: "short", timeZone: zone }).format(Date.UTC(2026, 6, 15)))
    };

    const raw = { zone, dateOffsets, intlOffsets, disagreements, transitions2026: transitions, parsing, formats, currentOffsetMinutes: -new Date().getTimezoneOffset() };
    // The current offset is left out of normalized: it flips at daylight-saving changes without the setting changing
    return {
        raw,
        normalized: { zone, dateOffsets, transitions2026: transitions, intlAgreesWithDate: disagreements.length === 0, parsing, formats },
        notes: ["Historical and future offsets expose the time zone database rules behind the zone name, and the Intl-versus-Date comparison flags spoofed zones. All of it is configuration: it changes when the user changes time zone."]
    };
}

registerTest({ id: "hardwareEnvironment", category: "static", groups: ["cpu"], run: getHardwareEnvironment });
registerTest({ id: "browserSettings", category: "configuration", groups: [], run: getBrowserSettings });
registerTest({ id: "storageEnvironment", category: "configuration", groups: [], run: getStorageEnvironment });
registerTest({ id: "screenDetails", category: "configuration", groups: ["display"], run: getScreenDetailsTest, optIn: "screenDetails", timeoutMs: 20000 });
registerTest({ id: "apiAvailability", category: "static", groups: ["browserEngine"], run: getApiAvailability });
registerTest({ id: "deviceAvailability", category: "configuration", groups: [], run: getDeviceAvailability, timeoutMs: 15000 });
registerTest({ id: "indexedDbBehavior", category: "behavioral", groups: ["browserEngine"], run: getIndexedDbBehavior, timeoutMs: 15000 });
registerTest({ id: "cacheApiBehavior", category: "behavioral", groups: ["browserEngine"], run: getCacheApiBehavior, timeoutMs: 15000 });
registerTest({ id: "compressionBehavior", category: "behavioral", groups: ["browserEngine"], run: getCompressionBehavior, timeoutMs: 15000 });
registerTest({ id: "regexpBehavior", category: "behavioral", groups: ["browserEngine"], run: getRegexpBehavior });
registerTest({ id: "intlData", category: "static", groups: ["browserEngine"], run: getIntlData });
registerTest({ id: "localeSettings", category: "configuration", groups: ["locale"], run: getLocaleSettings });
registerTest({ id: "timezoneBehavior", category: "configuration", groups: ["locale"], run: getTimezoneBehavior });
