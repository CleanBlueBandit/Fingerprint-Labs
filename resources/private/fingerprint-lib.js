// Defined first so it is available as soon as this file loads
const FINGERPRINT_WARNING =
`PRIVACY WARNING
This test collects technical and potentially identifying data from your browser, device and network, including:
  - your public IP address and the request headers your browser sends (as seen by this server)
  - local and public network addresses exposed through WebRTC (via a third-party STUN server)
  - hardware, GPU, audio, font, display and locale characteristics
  - installed plugins, connected media devices (types and counts), permission states, storage and battery status
  - optionally, your precise location (only if you opt in AND approve the browser prompt)
Results are shown in your browser and this script does not store or upload them. The server you are connected to sees your IP address and request headers when you run the test, and the WebRTC test contacts a third-party STUN server.
Combined, this data can identify you. Do not share the raw results publicly.`;
window.FINGERPRINT_WARNING = FINGERPRINT_WARNING;

function getBrowserInfo() {
    const ua = navigator.userAgent;
    const uaData = navigator.userAgentData;

    return {
        userAgent: ua,

        clientHints: uaData ? {
            brands: uaData.brands,
            mobile: uaData.mobile,
            platform: uaData.platform
        } : null,

        platform: navigator.platform,

        languages: navigator.languages,
        language: navigator.language,

        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,

        cookieEnabled: navigator.cookieEnabled
    };
}

async function getDetailedClientHints() {
    if (!navigator.userAgentData) return null;

    return await navigator.userAgentData.getHighEntropyValues([
        "architecture",
        "bitness",
        "model",
        "platformVersion",
        "fullVersionList",
        "wow64"
    ]);
}

function getDisplayInfo() {
    return {
        // Physical screen dimensions (CSS pixels)
        screen: {
            width: screen.width,
            height: screen.height,

            // Available dimensions excluding OS-managed areas
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,

            // Color depth
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth
        },

        // Browser viewport dimensions
        viewport: {
            width: window.innerWidth,
            height: window.innerHeight
        },

        // Device pixel ratio
        devicePixelRatio: window.devicePixelRatio,

        // Screen orientation
        orientation: screen.orientation ? {
            type: screen.orientation.type,
            angle: screen.orientation.angle
        } : null
    };
}

// Fallback hash (cyrb53) for non-secure contexts where crypto.subtle is unavailable
function cyrb53(str, seed = 0) {
    let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
    for (let i = 0; i < str.length; i++) {
        const ch = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
}

async function hashString(str) {
    if (window.crypto && crypto.subtle) {
        const buf = new TextEncoder().encode(str);
        const hash = await crypto.subtle.digest("SHA-256", buf);
        return {
            algorithm: "SHA-256",
            value: Array.from(new Uint8Array(hash))
                .map(b => b.toString(16).padStart(2, "0"))
                .join("")
        };
    }
    return { algorithm: "cyrb53", value: cyrb53(str) };
}

async function getCanvasFingerprint() {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");

    canvas.width = 300;
    canvas.height = 150;

    // Background
    ctx.fillStyle = "#f60";
    ctx.fillRect(10, 10, 100, 50);

    // Gradient
    const gradient = ctx.createLinearGradient(0, 0, 200, 100);
    gradient.addColorStop(0, "blue");
    gradient.addColorStop(1, "red");

    ctx.fillStyle = gradient;
    ctx.fillRect(120, 10, 100, 50);

    // Text rendering
    ctx.font = "18px Arial";
    ctx.fillStyle = "#000";
    ctx.fillText("Fingerprint test 123!", 10, 100);

    // Extract rendered pixel data
    const dataUrl = canvas.toDataURL();
    const hash = await hashString(dataUrl);

    return {
        hashAlgorithm: hash.algorithm,
        hash: hash.value,
        dataUrlLength: dataUrl.length,
        dataUrlPreview: dataUrl.slice(0, 60) + "...",
        width: canvas.width,
        height: canvas.height
    };
}

// ---------------------------------------------------------------------------
// D. Audio
// ---------------------------------------------------------------------------

// AudioContext support
function getAudioSupport() {
    return {
        AudioContext: typeof window.AudioContext !== "undefined",
        webkitAudioContext: typeof window.webkitAudioContext !== "undefined",
        OfflineAudioContext: typeof window.OfflineAudioContext !== "undefined",
        webkitOfflineAudioContext: typeof window.webkitOfflineAudioContext !== "undefined",
        AudioWorklet: typeof window.AudioWorklet !== "undefined",
        mediaDevices: !!(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices)
    };
}

// Audio sample rate + output characteristics
async function getAudioOutputInfo() {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return null;

    let ctx;
    try {
        ctx = new AC();
        const dest = ctx.destination;
        const analyser = ctx.createAnalyser();

        return {
            sampleRate: ctx.sampleRate,
            state: ctx.state, // often "suspended" until a user gesture
            baseLatency: ctx.baseLatency ?? null,
            outputLatency: ctx.outputLatency ?? null,
            destination: {
                maxChannelCount: dest.maxChannelCount,
                channelCount: dest.channelCount,
                channelCountMode: dest.channelCountMode,
                channelInterpretation: dest.channelInterpretation,
                numberOfInputs: dest.numberOfInputs,
                numberOfOutputs: dest.numberOfOutputs
            },
            analyser: {
                fftSize: analyser.fftSize,
                frequencyBinCount: analyser.frequencyBinCount,
                minDecibels: analyser.minDecibels,
                maxDecibels: analyser.maxDecibels,
                smoothingTimeConstant: analyser.smoothingTimeConstant
            }
        };
    } catch (e) {
        return { error: String(e) };
    } finally {
        if (ctx && ctx.close) ctx.close().catch(() => {});
    }
}

// Audio rendering fingerprint (offline render, no sound is played)
async function getAudioFingerprint() {
    const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!OAC) return null;

    try {
        const sampleRate = 44100;
        const ctx = new OAC(1, sampleRate, sampleRate); // 1 channel, 1 second

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

        const buffer = await ctx.startRendering();
        const samples = buffer.getChannelData(0);

        // Numeric summary of a slice of the rendered signal
        let sum = 0;
        for (let i = 4500; i < 5000; i++) sum += Math.abs(samples[i]);

        // Hash of the full rendered buffer
        const hash = await hashString(Array.from(samples).join(","));

        return {
            sampleSum: sum,
            hashAlgorithm: hash.algorithm,
            hash: hash.value,
            bufferLength: samples.length,
            first5Samples: Array.from(samples.slice(4500, 4505))
        };
    } catch (e) {
        return { error: String(e) };
    }
}

// ---------------------------------------------------------------------------
// E. Hardware and capabilities
// ---------------------------------------------------------------------------

// hardwareConcurrency, deviceMemory, maxTouchPoints, touch support
function getHardwareInfo() {
    const mq = (q) => (window.matchMedia ? window.matchMedia(q).matches : null);

    return {
        hardwareConcurrency: navigator.hardwareConcurrency ?? null,
        // Chromium only; capped/bucketed value in GB (0.25 to 8), null elsewhere
        deviceMemory: navigator.deviceMemory ?? null,
        maxTouchPoints: navigator.maxTouchPoints ?? 0,
        touch: {
            ontouchstart: "ontouchstart" in window,
            TouchEvent: typeof window.TouchEvent !== "undefined",
            PointerEvent: typeof window.PointerEvent !== "undefined",
            pointerCoarse: mq("(pointer: coarse)"),
            pointerFine: mq("(pointer: fine)"),
            anyPointerCoarse: mq("(any-pointer: coarse)"),
            hoverNone: mq("(hover: none)"),
            anyHover: mq("(any-hover: hover)")
        }
    };
}

// Which browser APIs exist (presence checks only, nothing is invoked)
function getSupportedApis() {
    const checks = {
        // Storage
        localStorage: () => "localStorage" in window,
        sessionStorage: () => "sessionStorage" in window,
        indexedDB: () => "indexedDB" in window,
        caches: () => "caches" in window,
        // Workers / background
        serviceWorker: () => "serviceWorker" in navigator,
        Worker: () => typeof Worker !== "undefined",
        SharedWorker: () => typeof SharedWorker !== "undefined",
        BroadcastChannel: () => typeof BroadcastChannel !== "undefined",
        // Graphics / media
        WebGL: () => typeof WebGLRenderingContext !== "undefined",
        WebGL2: () => typeof WebGL2RenderingContext !== "undefined",
        WebGPU: () => "gpu" in navigator,
        OffscreenCanvas: () => typeof OffscreenCanvas !== "undefined",
        WebAssembly: () => typeof WebAssembly !== "undefined",
        MediaRecorder: () => typeof MediaRecorder !== "undefined",
        MediaSource: () => typeof MediaSource !== "undefined",
        SpeechSynthesis: () => "speechSynthesis" in window,
        SpeechRecognition: () =>
            "SpeechRecognition" in window || "webkitSpeechRecognition" in window,
        // Device / sensors
        geolocation: () => "geolocation" in navigator,
        DeviceMotionEvent: () => typeof DeviceMotionEvent !== "undefined",
        DeviceOrientationEvent: () => typeof DeviceOrientationEvent !== "undefined",
        Bluetooth: () => "bluetooth" in navigator,
        USB: () => "usb" in navigator,
        Serial: () => "serial" in navigator,
        HID: () => "hid" in navigator,
        Gamepad: () => "getGamepads" in navigator,
        Vibration: () => "vibrate" in navigator,
        Battery: () => "getBattery" in navigator,
        NetworkInformation: () => "connection" in navigator,
        // Platform
        Notification: () => "Notification" in window,
        PushManager: () => "PushManager" in window,
        Clipboard: () => "clipboard" in navigator,
        Share: () => "share" in navigator,
        Permissions: () => "permissions" in navigator,
        CredentialsContainer: () => "credentials" in navigator,
        PublicKeyCredential: () => typeof PublicKeyCredential !== "undefined",
        FullscreenAPI: () => "fullscreenEnabled" in document,
        PaymentRequest: () => typeof PaymentRequest !== "undefined",
        FileSystemAccess: () => "showOpenFilePicker" in window,
        // Web platform
        fetch: () => typeof fetch === "function",
        WebSocket: () => typeof WebSocket !== "undefined",
        IntersectionObserver: () => typeof IntersectionObserver !== "undefined",
        ResizeObserver: () => typeof ResizeObserver !== "undefined",
        MutationObserver: () => typeof MutationObserver !== "undefined",
        PerformanceObserver: () => typeof PerformanceObserver !== "undefined",
        CSSSupports: () => !!(window.CSS && CSS.supports),
        Intl: () => typeof Intl !== "undefined",
        structuredClone: () => typeof structuredClone === "function",
        // Privacy-related signals
        doNotTrack: () => navigator.doNotTrack ?? null,
        globalPrivacyControl: () => navigator.globalPrivacyControl ?? null,
        webdriver: () => navigator.webdriver ?? null
    };

    const result = {};
    for (const [name, check] of Object.entries(checks)) {
        try {
            result[name] = check();
        } catch (e) {
            result[name] = null;
        }
    }
    return result;
}

// WebRTC availability only. No RTCPeerConnection is created and no ICE
// gathering happens, so no IP addresses are ever touched.
function getWebRTCAvailability() {
    const PC = window.RTCPeerConnection || window.webkitRTCPeerConnection ||
        window.mozRTCPeerConnection;

    const codecs = (kind) => {
        try {
            if (window.RTCRtpSender && RTCRtpSender.getCapabilities) {
                const caps = RTCRtpSender.getCapabilities(kind);
                return caps ? caps.codecs.map(c => c.mimeType) : null;
            }
        } catch (e) { /* ignore */ }
        return null;
    };

    return {
        RTCPeerConnection: typeof window.RTCPeerConnection !== "undefined",
        prefixedRTCPeerConnection: !!(window.webkitRTCPeerConnection || window.mozRTCPeerConnection),
        anyRTCPeerConnection: !!PC,
        RTCSessionDescription: typeof window.RTCSessionDescription !== "undefined",
        RTCIceCandidate: typeof window.RTCIceCandidate !== "undefined",
        RTCDataChannel: typeof window.RTCDataChannel !== "undefined",
        RTCRtpSender: typeof window.RTCRtpSender !== "undefined",
        RTCRtpReceiver: typeof window.RTCRtpReceiver !== "undefined",
        getUserMedia: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
        getDisplayMedia: !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia),
        enumerateDevices: !!(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices),
        senderCodecs: {
            audio: codecs("audio"),
            video: codecs("video")
        }
    };
}

// ---------------------------------------------------------------------------
// F. Extended data collection (network, GPU, fonts, devices, permissions...)
// ---------------------------------------------------------------------------

async function fetchWithTimeout(url, ms = 4000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try {
        return await fetch(url, { signal: ctrl.signal, cache: "no-store" });
    } finally {
        clearTimeout(t);
    }
}

// What this server sees about your request: IP, headers, header order, TLS...
// Served by routes/fingerprint.js. The response asks the browser to send extra
// client hints on later requests, so when it does we call once more to capture them.
async function getServerView(url = "/fingerprint/info") {
    const call = async () => {
        const sentAt = Date.now();
        const response = await fetchWithTimeout(url);
        const receivedAt = Date.now();
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        const serverMs = Date.parse(data.serverTime);
        data.clientTiming = {
            roundTripMs: receivedAt - sentAt,
            // Server clock minus client clock at the request midpoint (includes network jitter)
            clockSkewMs: Number.isNaN(serverMs)
                ? null
                : Math.round(serverMs - (sentAt + receivedAt) / 2)
        };
        return { data, acceptCH: response.headers.get("accept-ch") };
    };

    const first = await call();
    if (first.acceptCH) {
        try {
            return (await call()).data;
        } catch (e) {
            return first.data;
        }
    }
    return first.data;
}

// Compare what the browser says about itself with what the server received.
// Mismatches suggest spoofing, an extension, or a proxy/VPN in the path.
function getConsistency(result) {
    const sv = result.serverView;
    if (!sv || sv.error) return null;

    const headers = sv.headers || {};
    const serverLangs = ((sv.parsed && sv.parsed.acceptLanguage) || [])
        .map(l => l.tag.toLowerCase());
    const clientLangs = (navigator.languages || []).map(l => l.toLowerCase());

    const uaPlatform = navigator.userAgentData && navigator.userAgentData.platform;
    const hintPlatform = headers["sec-ch-ua-platform"]
        ? headers["sec-ch-ua-platform"].replace(/"/g, "")
        : null;

    // Public addresses WebRTC found vs the IP the server saw
    const serverIp = sv.ip && sv.ip.client;
    const rtcPublic = result.webrtcIPs && result.webrtcIPs.publicAddresses;
    let webrtcPublicMatchesServerIp = null;
    if (serverIp && serverIp.class === "public" && rtcPublic && rtcPublic.length) {
        webrtcPublicMatchesServerIp = rtcPublic.every(a => a === serverIp.address);
    }

    return {
        userAgentMatches: headers["user-agent"] === navigator.userAgent,
        primaryLanguageMatches: serverLangs.length
            ? serverLangs[0] === (navigator.language || "").toLowerCase()
            : null,
        languageListMatches: serverLangs.length
            ? JSON.stringify(serverLangs) === JSON.stringify(clientLangs)
            : null,
        clientHintsPlatformMatches: uaPlatform && hintPlatform
            ? uaPlatform === hintPlatform
            : null,
        webrtcPublicMatchesServerIp
    };
}

// "candidate:<found> <comp> <proto> <prio> <addr> <port> typ <type> ..."
function parseIceCandidate(line) {
    const parts = line.replace(/^candidate:/, "").split(" ");
    if (parts.length < 8) return null;
    return {
        protocol: parts[2],
        address: parts[4],
        port: Number(parts[5]),
        type: parts[7] // host | srflx | prflx | relay
    };
}

// WebRTC IP exposure test: gathers ICE candidates with a STUN server.
// "host" = local addresses (often replaced by random .local mDNS names),
// "srflx" = public address as seen by the STUN server.
function getWebRTCIPs(stunServers = ["stun:stun.l.google.com:19302"], timeoutMs = 4000) {
    return new Promise((resolve) => {
        const PC = window.RTCPeerConnection || window.webkitRTCPeerConnection ||
            window.mozRTCPeerConnection;
        if (!PC) return resolve(null);

        const found = new Map();
        let pc = null;
        let timer = null;
        let finished = false;

        const finish = (extra = {}) => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            try { if (pc) pc.close(); } catch (e) { /* ignore */ }
            const candidates = Array.from(found.values());
            resolve({
                stunServers,
                candidates,
                hostAddresses: candidates.filter(c => c.type === "host").map(c => c.address),
                publicAddresses: candidates.filter(c => c.type === "srflx").map(c => c.address),
                mdnsObfuscated: candidates.some(c => c.address.endsWith(".local")),
                ...extra
            });
        };

        timer = setTimeout(() => finish({ timedOut: true }), timeoutMs);

        try {
            pc = new PC({ iceServers: [{ urls: stunServers }] });
            pc.createDataChannel("fp");
            pc.onicecandidate = (e) => {
                if (!e.candidate) return finish();
                const c = parseIceCandidate(e.candidate.candidate);
                if (c) found.set(`${c.address}|${c.port}|${c.type}`, c);
            };
            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(err => finish({ error: String(err) }));
        } catch (err) {
            finish({ error: String(err) });
        }
    });
}

function getNetworkInfo() {
    const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    return {
        onLine: navigator.onLine,
        connection: c ? {
            effectiveType: c.effectiveType ?? null,
            type: c.type ?? null,
            downlink: c.downlink ?? null,
            downlinkMax: c.downlinkMax ?? null,
            rtt: c.rtt ?? null,
            saveData: c.saveData ?? null
        } : null
    };
}

// GPU / WebGL details (unmasked renderer is very identifying)
function getWebGLInfo() {
    const out = {};
    for (const type of ["webgl", "webgl2"]) {
        const canvas = document.createElement("canvas");
        const gl = canvas.getContext(type);
        if (!gl) { out[type] = null; continue; }
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        const attrs = gl.getContextAttributes() || {};
        out[type] = {
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            vendor: gl.getParameter(gl.VENDOR),
            renderer: gl.getParameter(gl.RENDERER),
            unmaskedVendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : null,
            unmaskedRenderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : null,
            antialias: attrs.antialias ?? null,
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
            maxViewportDims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS)),
            maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
            maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
            maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
            maxFragmentUniformVectors: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
            aliasedLineWidthRange: Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)),
            aliasedPointSizeRange: Array.from(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)),
            extensions: gl.getSupportedExtensions()
        };
    }
    return out;
}

// Installed-font detection by measuring text width against baseline fonts
function getInstalledFonts() {
    const candidates = [
        "Arial", "Arial Black", "Arial Narrow", "Calibri", "Cambria", "Candara",
        "Consolas", "Constantia", "Corbel", "Courier New", "Comic Sans MS",
        "Franklin Gothic Medium", "Gabriola", "Georgia", "Impact", "Lucida Console",
        "Lucida Sans Unicode", "Microsoft Sans Serif", "Palatino Linotype", "Segoe UI",
        "Segoe Print", "Segoe Script", "Segoe UI Emoji", "Sylfaen", "Tahoma",
        "Times New Roman", "Trebuchet MS", "Verdana", "Helvetica", "Helvetica Neue",
        "Menlo", "Monaco", "Geneva", "Optima", "Futura", "Gill Sans", "Avenir",
        "American Typewriter", "Baskerville", "Didot", "Hoefler Text", "SF Pro",
        "Apple Color Emoji", "Noto Sans", "Noto Serif", "Roboto", "Open Sans",
        "Ubuntu", "DejaVu Sans", "Liberation Sans", "Cantarell", "Droid Sans",
        "Fira Sans", "Source Sans Pro", "Lato", "Montserrat", "Oswald", "Raleway",
        "PT Sans", "MS Gothic", "SimSun", "Microsoft YaHei", "Malgun Gothic",
        "Yu Gothic", "Meiryo", "Noto Sans CJK JP"
    ];
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    const text = "mmmmmmmmmmlliWwQ@#0123456789";
    const bases = ["monospace", "sans-serif", "serif"];
    const measure = (font) => {
        ctx.font = `72px ${font}`;
        return ctx.measureText(text).width;
    };
    const baseWidths = bases.map(measure);
    const installed = candidates.filter(f =>
        bases.some((b, i) => measure(`'${f}', ${b}`) !== baseWidths[i])
    );
    return { tested: candidates.length, installed };
}

// Media devices: kinds and counts (labels stay empty without camera/mic permission)
async function getMediaDevices() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return null;
    const devices = await navigator.mediaDevices.enumerateDevices();
    const counts = {};
    devices.forEach(d => { counts[d.kind] = (counts[d.kind] || 0) + 1; });
    return {
        counts,
        labelsVisible: devices.some(d => !!d.label),
        devices: devices.map(d => ({
            kind: d.kind,
            label: d.label || null,
            hasDeviceId: !!d.deviceId,
            hasGroupId: !!d.groupId
        }))
    };
}

// Permission states (query only, never triggers a prompt)
async function getPermissionStates() {
    if (!navigator.permissions || !navigator.permissions.query) return null;
    const names = [
        "geolocation", "notifications", "camera", "microphone", "clipboard-read",
        "clipboard-write", "persistent-storage", "push", "midi", "accelerometer",
        "gyroscope", "magnetometer", "background-sync", "screen-wake-lock",
        "storage-access", "ambient-light-sensor"
    ];
    const out = {};
    for (const name of names) {
        try {
            out[name] = (await navigator.permissions.query({ name })).state;
        } catch (e) {
            out[name] = null; // unsupported name in this browser
        }
    }
    return out;
}

// Precise location. Opt-in only: the browser shows a permission prompt.
function getGeolocation(timeoutMs = 10000) {
    return new Promise((resolve) => {
        if (!navigator.geolocation) return resolve(null);
        navigator.geolocation.getCurrentPosition(
            (p) => resolve({
                latitude: p.coords.latitude,
                longitude: p.coords.longitude,
                accuracy: p.coords.accuracy,
                altitude: p.coords.altitude,
                timestamp: p.timestamp
            }),
            (err) => resolve({ error: err.message, code: err.code }),
            { timeout: timeoutMs, maximumAge: 0 }
        );
    });
}

async function getStorageAndPower() {
    const out = { storage: null, battery: null, jsHeap: null };
    if (navigator.storage && navigator.storage.estimate) {
        const e = await navigator.storage.estimate();
        out.storage = { quota: e.quota ?? null, usage: e.usage ?? null };
    }
    if (navigator.getBattery) {
        const b = await navigator.getBattery();
        out.battery = {
            charging: b.charging,
            level: b.level,
            chargingTime: b.chargingTime,
            dischargingTime: b.dischargingTime
        };
    }
    if (performance.memory) {
        out.jsHeap = {
            jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
            totalJSHeapSize: performance.memory.totalJSHeapSize,
            usedJSHeapSize: performance.memory.usedJSHeapSize
        };
    }
    return out;
}

function getPluginsAndMimeTypes() {
    return {
        pdfViewerEnabled: navigator.pdfViewerEnabled ?? null,
        plugins: Array.from(navigator.plugins || []).map(p => ({
            name: p.name, filename: p.filename, description: p.description
        })),
        mimeTypes: Array.from(navigator.mimeTypes || []).map(m => m.type)
    };
}

function getMediaCodecSupport() {
    const video = document.createElement("video");
    const audio = document.createElement("audio");
    const videoTypes = [
        'video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="hev1.1.6.L93.B0"',
        'video/mp4; codecs="av01.0.05M.08"', 'video/webm; codecs="vp8"',
        'video/webm; codecs="vp9"', 'video/ogg; codecs="theora"'
    ];
    const audioTypes = [
        "audio/mpeg", 'audio/mp4; codecs="mp4a.40.2"', 'audio/ogg; codecs="vorbis"',
        'audio/ogg; codecs="opus"', 'audio/webm; codecs="opus"', "audio/wav",
        "audio/flac", "audio/aac"
    ];
    const out = { video: {}, audio: {}, mediaSource: {}, mediaRecorder: {} };
    videoTypes.forEach(t => {
        out.video[t] = video.canPlayType(t) || "no";
        if (window.MediaSource) out.mediaSource[t] = MediaSource.isTypeSupported(t);
        if (window.MediaRecorder) out.mediaRecorder[t] = MediaRecorder.isTypeSupported(t);
    });
    audioTypes.forEach(t => { out.audio[t] = audio.canPlayType(t) || "no"; });
    return out;
}

// Display and accessibility preferences + locale/timezone details
function getPreferencesAndLocale() {
    const mq = (q) => (window.matchMedia ? window.matchMedia(q).matches : null);
    const dtf = Intl.DateTimeFormat().resolvedOptions();
    const year = new Date().getFullYear();
    return {
        preferences: {
            darkMode: mq("(prefers-color-scheme: dark)"),
            reducedMotion: mq("(prefers-reduced-motion: reduce)"),
            reducedTransparency: mq("(prefers-reduced-transparency: reduce)"),
            highContrast: mq("(prefers-contrast: more)"),
            forcedColors: mq("(forced-colors: active)"),
            invertedColors: mq("(inverted-colors: inverted)"),
            colorGamutP3: mq("(color-gamut: p3)"),
            colorGamutRec2020: mq("(color-gamut: rec2020)"),
            hdr: mq("(dynamic-range: high)"),
            standalone: mq("(display-mode: standalone)")
        },
        locale: {
            locale: dtf.locale,
            calendar: dtf.calendar,
            numberingSystem: dtf.numberingSystem,
            timeZone: dtf.timeZone,
            hourCycle: dtf.hourCycle ?? null,
            timezoneOffsetMinutes: new Date().getTimezoneOffset(),
            januaryOffset: new Date(year, 0, 1).getTimezoneOffset(),
            julyOffset: new Date(year, 6, 1).getTimezoneOffset()
        }
    };
}

// Installed text-to-speech voices (differ by OS and language packs)
function getSpeechVoices(timeoutMs = 1500) {
    return new Promise((resolve) => {
        if (!("speechSynthesis" in window)) return resolve(null);
        const done = () => resolve(
            speechSynthesis.getVoices().map(v => ({
                name: v.name, lang: v.lang, local: v.localService, default: v.default
            }))
        );
        if (speechSynthesis.getVoices().length) return done();
        const t = setTimeout(done, timeoutMs);
        speechSynthesis.addEventListener("voiceschanged", () => {
            clearTimeout(t);
            done();
        }, { once: true });
    });
}

function getTimerResolution() {
    const deltas = [];
    let last = performance.now();
    for (let i = 0; i < 100000 && deltas.length < 20; i++) {
        const now = performance.now();
        if (now !== last) { deltas.push(now - last); last = now; }
    }
    return {
        minDelta: deltas.length ? Math.min(...deltas) : null,
        samples: deltas.length
    };
}

function getNavigatorExtras() {
    return {
        vendor: navigator.vendor,
        vendorSub: navigator.vendorSub,
        product: navigator.product,
        productSub: navigator.productSub,
        appName: navigator.appName,
        appCodeName: navigator.appCodeName,
        appVersion: navigator.appVersion,
        oscpu: navigator.oscpu ?? null,
        buildID: navigator.buildID ?? null,
        javaEnabled: typeof navigator.javaEnabled === "function" ? navigator.javaEnabled() : null,
        webdriver: navigator.webdriver ?? null,
        doNotTrack: navigator.doNotTrack ?? null,
        globalPrivacyControl: navigator.globalPrivacyControl ?? null,
        onLine: navigator.onLine,
        isSecureContext: window.isSecureContext,
        crossOriginIsolated: window.crossOriginIsolated ?? null,
        historyLength: history.length,
        referrer: document.referrer || null,
        characterSet: document.characterSet,
        window: {
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight,
            screenX: window.screenX,
            screenY: window.screenY
        }
    };
}

// ---------------------------------------------------------------------------
// Entry point: call this from your "Start fingerprint" button
// ---------------------------------------------------------------------------

// Runs one collector; a failure in one section never breaks the others
async function safe(fn) {
    try {
        return await fn();
    } catch (e) {
        return { error: String(e) };
    }
}

/**
 * runFingerprint({
 *   consent: true,          // REQUIRED. Pass true only after the user has seen FINGERPRINT_WARNING.
 *   network: true,          // what this server sees (IP, headers) + WebRTC STUN candidates
 *   serverUrl: '/fingerprint/info', // endpoint that reports the request as the server received it
 *   geolocation: false,     // precise location; triggers a browser permission prompt
 *   stunServers: [...],     // optional STUN URLs
 *   onProgress: (name) => {} // optional progress callback
 * })
 */
async function runFingerprint(options = {}) {
    const opts = {
        consent: false,
        network: true,
        geolocation: false,
        stunServers: ["stun:stun.l.google.com:19302"],
        serverUrl: "/fingerprint/info",
        onProgress: null,
        ...options
    };

    if (opts.consent !== true) {
        throw new Error(
            "Consent required: show FINGERPRINT_WARNING to the user and call runFingerprint({ consent: true })."
        );
    }

    const step = (name, fn) => {
        if (typeof opts.onProgress === "function") {
            try { opts.onProgress(name); } catch (e) { /* ignore */ }
        }
        return safe(fn);
    };

    const result = {
        timestamp: new Date().toISOString(),
        warningAcknowledged: true,

        // A-E
        browser: await step("browser", getBrowserInfo),
        clientHints: await step("clientHints", getDetailedClientHints),
        display: await step("display", getDisplayInfo),
        canvas: await step("canvas", getCanvasFingerprint),
        audio: {
            support: await step("audio support", getAudioSupport),
            output: await step("audio output", getAudioOutputInfo),
            fingerprint: await step("audio fingerprint", getAudioFingerprint)
        },
        hardware: await step("hardware", getHardwareInfo),
        apis: await step("apis", getSupportedApis),
        webrtc: await step("webrtc availability", getWebRTCAvailability),

        // F
        webgl: await step("webgl", getWebGLInfo),
        fonts: await step("fonts", getInstalledFonts),
        plugins: await step("plugins", getPluginsAndMimeTypes),
        codecs: await step("codecs", getMediaCodecSupport),
        speechVoices: await step("speech voices", getSpeechVoices),
        prefsAndLocale: await step("preferences", getPreferencesAndLocale),
        navigatorExtras: await step("navigator extras", getNavigatorExtras),
        timer: await step("timer resolution", getTimerResolution),
        mediaDevices: await step("media devices", getMediaDevices),
        permissions: await step("permissions", getPermissionStates),
        storageAndPower: await step("storage and power", getStorageAndPower),
        networkInfo: await step("network info", getNetworkInfo)
    };

    if (opts.network) {
        result.serverView = await step("server view", () => getServerView(opts.serverUrl));
        result.webrtcIPs = await step("webrtc ip candidates",
            () => getWebRTCIPs(opts.stunServers));
        result.consistency = await step("consistency checks", () => getConsistency(result));
    }

    if (opts.geolocation) {
        result.geolocation = await step("geolocation", getGeolocation);
    }

    // Hash of device traits that should stay stable between runs.
    // Excludes timestamp, IPs, permissions, battery, storage and location.
    const stable = {
        browser: result.browser,
        clientHints: result.clientHints,
        screen: result.display && result.display.screen,
        canvas: result.canvas,
        audio: result.audio,
        hardware: result.hardware,
        apis: result.apis,
        webrtc: result.webrtc,
        webgl: result.webgl,
        fonts: result.fonts,
        plugins: result.plugins,
        codecs: result.codecs,
        speechVoices: result.speechVoices,
        prefsAndLocale: result.prefsAndLocale
    };
    result.combinedHash = await hashString(JSON.stringify(stable));

    return result;
}

// Make it reachable from inline handlers / other scripts
window.runFingerprint = runFingerprint;
