// Defined first so it is available as soon as this file loads
const FINGERPRINT_WARNING =
`PRIVACY WARNING
This test collects technical and potentially identifying data from your browser, device and network, including:
  - your public IP address and the request headers your browser sends (as seen by this server)
  - local and public network addresses exposed through WebRTC (via a third-party STUN server)
  - hardware, GPU (including WebGPU adapter details), audio, font, display and locale characteristics
  - CSS media features (colour gamut, HDR, contrast, pointer and hover capabilities)
  - how your JavaScript engine does maths, sorting and number formatting
  - how your system renders text and emoji (metrics, anti-aliasing, subpixel positioning)
  - how your GPU renders a test scene and computes maths (WebGPU, WebGL shader precision)
  - which CSS features your browser supports, plus system colours, fonts and scrollbar size
  - how your audio engine renders a test tone, how your GPU renders a WebGL test scene, and which fonts render glyphs in several scripts
  - WebAssembly, WebCodecs and MediaCapabilities support (including hardware decoding hints), device and sensor API availability, and how IndexedDB, Cache, compression, RegExp, Intl and date functions behave
  - optionally, details of every connected screen (only if you opt in AND approve the browser prompt)
  - when this server terminates TLS itself, the TLS handshake your browser sent (JA3/JA4)
  - installed plugins, connected media devices (types and counts), permission states, storage and battery status
  - optionally, your precise location (only if you opt in AND approve the browser prompt)
Results are shown in your browser and are not uploaded unless you press "Save to my account", which stores the full result against your account on this server until you delete it. The server you are connected to sees your IP address and request headers when you run the test, and the WebRTC test contacts a third-party STUN server.
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
        "uaFullVersion",
        "formFactors",
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
        } : null,

        // Visual viewport: the area actually visible, which shrinks with pinch zoom and on-screen
        // keyboards. Kept apart from screen (the physical display) on purpose.
        visualViewport: window.visualViewport ? {
            width: window.visualViewport.width,
            height: window.visualViewport.height,
            scale: window.visualViewport.scale,
            offsetLeft: window.visualViewport.offsetLeft,
            offsetTop: window.visualViewport.offsetTop
        } : null,

        // Browser zoom changes screen.width (CSS pixels) and devicePixelRatio in opposite
        // directions, so their product stays put. Long side first, so rotation does not matter.
        normalized: (() => {
            const dpr = window.devicePixelRatio || 1;
            const pair = (a, b) => [Math.round(Math.max(a, b) * dpr), Math.round(Math.min(a, b) * dpr)];
            return {
                screenDevicePixels: pair(screen.width, screen.height),
                availDevicePixels: pair(screen.availWidth, screen.availHeight),
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth,
                orientationType: screen.orientation ? screen.orientation.type.replace(/-(primary|secondary)$/, "") : null
            };
        })()
    };
}

// Pure-JS SHA-256 for non-secure contexts, where crypto.subtle is unavailable
// (plain http on anything but localhost). It keeps every hash SHA-256, so values
// stay comparable between secure and insecure origins.
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha256Fallback(bytes) {
    const h = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    const bitLength = bytes.length * 8;
    const paddedLength = ((bytes.length + 9 + 63) >> 6) << 6;
    const data = new Uint8Array(paddedLength);
    data.set(bytes);
    data[bytes.length] = 0x80;
    const view = new DataView(data.buffer);
    view.setUint32(paddedLength - 8, Math.floor(bitLength / 4294967296));
    view.setUint32(paddedLength - 4, bitLength >>> 0);

    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let offset = 0; offset < paddedLength; offset += 64) {
        for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, hh] = h;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) >>> 0;
            hh = g; g = f; f = e; e = (d + t1) >>> 0;
            d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    return Array.from(h).map(x => x.toString(16).padStart(8, "0")).join("");
}

const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");

// SHA-256 of raw bytes. Always SHA-256: crypto.subtle where available, pure JS otherwise.
async function hashBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        bytes = new Uint8Array(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength);
    }
    if (window.crypto && crypto.subtle) {
        return { algorithm: "SHA-256", value: toHex(await crypto.subtle.digest("SHA-256", bytes)) };
    }
    return { algorithm: "SHA-256", value: sha256Fallback(bytes) };
}

async function hashString(str) {
    return hashBytes(new TextEncoder().encode(str));
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
            // state and both latencies follow the output device and session, not the browser build
            volatile: ["state", "baseLatency", "outputLatency"],
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
    return {
        hardwareConcurrency: navigator.hardwareConcurrency ?? null,
        // Chromium only; capped/bucketed value in GB (0.25 to 8), null elsewhere
        deviceMemory: navigator.deviceMemory ?? null,
        maxTouchPoints: navigator.maxTouchPoints ?? 0,
        touch: {
            ontouchstart: "ontouchstart" in window,
            TouchEvent: typeof window.TouchEvent !== "undefined",
            PointerEvent: typeof window.PointerEvent !== "undefined"
            // pointer / hover media features are collected in mediaFeatures
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

    // Client hint headers (sent after Accept-CH) vs what the JS API reports
    const unq = (v) => (typeof v === "string" ? v.replace(/"/g, "") : null);
    const ch = result.clientHints || {};
    const hintMatch = (header, value) =>
        headers[header] && value !== undefined && value !== null && value !== ""
            ? unq(headers[header]) === String(value)
            : null;
    const mqScheme = window.matchMedia
        ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
        : null;
    const schemeHeader = unq(headers["sec-ch-prefers-color-scheme"]);

    return {
        userAgentMatches: headers["user-agent"] === navigator.userAgent,
        clientHintsArchitectureMatches: hintMatch("sec-ch-ua-arch", ch.architecture),
        clientHintsBitnessMatches: hintMatch("sec-ch-ua-bitness", ch.bitness),
        clientHintsPlatformVersionMatches: hintMatch("sec-ch-ua-platform-version", ch.platformVersion),
        prefersColorSchemeMatches: schemeHeader && mqScheme ? schemeHeader === mqScheme : null,
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

// getShaderPrecisionFormat() for every shader stage and precision qualifier.
// precision 0 for highFloat in the fragment stage means highp is not supported there.
function getShaderPrecision(gl) {
    const stages = { vertex: gl.VERTEX_SHADER, fragment: gl.FRAGMENT_SHADER };
    const types = {
        lowFloat: gl.LOW_FLOAT,
        mediumFloat: gl.MEDIUM_FLOAT,
        highFloat: gl.HIGH_FLOAT,
        lowInt: gl.LOW_INT,
        mediumInt: gl.MEDIUM_INT,
        highInt: gl.HIGH_INT
    };
    const out = {};
    for (const [stage, stageConst] of Object.entries(stages)) {
        out[stage] = {};
        for (const [name, typeConst] of Object.entries(types)) {
            const f = gl.getShaderPrecisionFormat(stageConst, typeConst);
            out[stage][name] = f
                ? { rangeMin: f.rangeMin, rangeMax: f.rangeMax, precision: f.precision }
                : null;
        }
    }
    return out;
}

// Extra limits beyond the ones listed in getWebGLInfo(). A name the context does not define
// (WebGL2-only constants on a WebGL1 context, for example) is skipped, not guessed.
const WEBGL_EXTRA_LIMITS = {
    webgl: [
        "MAX_TEXTURE_IMAGE_UNITS", "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "MAX_VERTEX_TEXTURE_IMAGE_UNITS",
        "MAX_CUBE_MAP_TEXTURE_SIZE", "SUBPIXEL_BITS"
    ],
    webgl2: [
        "MAX_TEXTURE_IMAGE_UNITS", "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "MAX_VERTEX_TEXTURE_IMAGE_UNITS",
        "MAX_CUBE_MAP_TEXTURE_SIZE", "SUBPIXEL_BITS",
        "MAX_SAMPLES", "MAX_3D_TEXTURE_SIZE", "MAX_ARRAY_TEXTURE_LAYERS", "MAX_COLOR_ATTACHMENTS", "MAX_DRAW_BUFFERS",
        "MAX_ELEMENTS_INDICES", "MAX_ELEMENTS_VERTICES", "MAX_FRAGMENT_INPUT_COMPONENTS", "MAX_VERTEX_OUTPUT_COMPONENTS",
        "MAX_FRAGMENT_UNIFORM_COMPONENTS", "MAX_VERTEX_UNIFORM_COMPONENTS", "MAX_VARYING_COMPONENTS",
        "MAX_PROGRAM_TEXEL_OFFSET", "MIN_PROGRAM_TEXEL_OFFSET", "MAX_TEXTURE_LOD_BIAS",
        "MAX_UNIFORM_BUFFER_BINDINGS", "MAX_UNIFORM_BLOCK_SIZE", "UNIFORM_BUFFER_OFFSET_ALIGNMENT",
        "MAX_VERTEX_UNIFORM_BLOCKS", "MAX_FRAGMENT_UNIFORM_BLOCKS", "MAX_COMBINED_UNIFORM_BLOCKS",
        "MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS", "MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS",
        "MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS", "MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS",
        "MAX_TRANSFORM_FEEDBACK_SEPARATE_COMPONENTS", "MAX_SERVER_WAIT_TIMEOUT"
    ]
};

function glParameterValue(gl, name) {
    if (gl[name] === undefined) return undefined;
    try {
        const v = gl.getParameter(gl[name]);
        return ArrayBuffer.isView(v) ? Array.from(v) : v;
    } catch (e) {
        return null;
    }
}

// Releases a context instead of leaving it to garbage collection (browsers cap live contexts)
function releaseGlContext(gl, canvas) {
    try {
        const lose = gl.getExtension("WEBGL_lose_context");
        if (lose) lose.loseContext();
    } catch (e) { /* ignore */ }
    canvas.width = 0;
    canvas.height = 0;
}

// GPU / WebGL details (unmasked renderer is very identifying).
// out[type] stays null when no context could be made; out.availability says why:
// "unsupported" (the interface does not exist) or "unavailable" (it exists but getContext failed).
function getWebGLInfo() {
    const out = { availability: {} };
    for (const type of ["webgl", "webgl2"]) {
        const iface = type === "webgl" ? "WebGLRenderingContext" : "WebGL2RenderingContext";
        const canvas = document.createElement("canvas");
        const gl = typeof window[iface] === "undefined" ? null : canvas.getContext(type);
        if (!gl) {
            out[type] = null;
            out.availability[type] = typeof window[iface] === "undefined"
                ? { status: "unsupported", reason: `${iface} is not defined` }
                : { status: "unavailable", reason: "getContext returned null (WebGL disabled, GPU blocklisted or context limit reached)" };
            continue;
        }
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        const attrs = gl.getContextAttributes() || {};
        const extensions = gl.getSupportedExtensions() || [];

        // Limits added to the original list
        const extraLimits = {};
        for (const name of WEBGL_EXTRA_LIMITS[type]) {
            const value = glParameterValue(gl, name);
            if (value !== undefined) extraLimits[name] = value;
        }

        // Limits that only exist when an extension is enabled
        const anisotropy = gl.getExtension("EXT_texture_filter_anisotropic");
        const drawBuffers = gl.getExtension("WEBGL_draw_buffers");
        const extensionLimits = {
            maxTextureAnisotropy: anisotropy ? gl.getParameter(anisotropy.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : null,
            maxDrawBuffersExt: drawBuffers ? gl.getParameter(drawBuffers.MAX_DRAW_BUFFERS_WEBGL) : null,
            maxColorAttachmentsExt: drawBuffers ? gl.getParameter(drawBuffers.MAX_COLOR_ATTACHMENTS_WEBGL) : null,
            compressedTextureFormats: (() => {
                try { return Array.from(gl.getParameter(gl.COMPRESSED_TEXTURE_FORMATS) || []).sort((x, y) => x - y); }
                catch (e) { return null; }
            })()
        };

        // Multisample counts the hardware offers for an RGBA8 renderbuffer (WebGL2 only)
        let rgba8Samples = null;
        if (type === "webgl2") {
            try { rgba8Samples = Array.from(gl.getInternalformatParameter(gl.RENDERBUFFER, gl.RGBA8, gl.SAMPLES)); }
            catch (e) { rgba8Samples = null; }
        }

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
            shaderPrecision: getShaderPrecision(gl),
            extensions: gl.getSupportedExtensions(),
            // added: texture units, MAX_SAMPLES and the other WebGL2 limits, extension limits
            limits: extraLimits,
            maxSamples: extraLimits.MAX_SAMPLES ?? null,
            rgba8RenderbufferSamples: rgba8Samples,
            extensionLimits,
            // What the default framebuffer got for the attributes requested above. This follows
            // the context attributes and the display, so treat it as configuration, not hardware.
            defaultFramebuffer: {
                redBits: gl.getParameter(gl.RED_BITS), greenBits: gl.getParameter(gl.GREEN_BITS),
                blueBits: gl.getParameter(gl.BLUE_BITS), alphaBits: gl.getParameter(gl.ALPHA_BITS),
                depthBits: gl.getParameter(gl.DEPTH_BITS), stencilBits: gl.getParameter(gl.STENCIL_BITS),
                samples: gl.getParameter(gl.SAMPLES)
            }
        };
        out.availability[type] = { status: "success", reason: null, extensionCount: extensions.length };
        releaseGlContext(gl, canvas);
    }

    // A context requested with failIfMajorPerformanceCaveat is refused when the browser would
    // fall back to a software renderer, so this separates hardware from software rendering.
    out.hardwareAcceleration = {};
    for (const type of ["webgl", "webgl2"]) {
        if (!out[type]) { out.hardwareAcceleration[type] = null; continue; }
        const canvas = document.createElement("canvas");
        const gl = canvas.getContext(type, { failIfMajorPerformanceCaveat: true });
        out.hardwareAcceleration[type] = !!gl;
        if (gl) releaseGlContext(gl, canvas);
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
        // usage changes as sites store data: it is not a device identifier
        out.storage = { quota: e.quota ?? null, usage: e.usage ?? null, usageIsVolatile: true };
        if (navigator.storage.persisted) {
            try { out.storage.persisted = await navigator.storage.persisted(); }
            catch (e2) { out.storage.persisted = null; }
        }
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
    const dtf = Intl.DateTimeFormat().resolvedOptions();
    const year = new Date().getFullYear();
    return {
        // All media-query based preferences live in mediaFeatures
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
// G. GPU (WebGPU), media features, JS engine behaviour, text rendering
// ---------------------------------------------------------------------------

// Shared helpers for the collectors below
const fmtNum = (v) => (Object.is(v, -0) ? "-0" : String(v));

function withTimeout(promise, ms, label = "operation") {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Runs fn with an off-screen host element and always removes it afterwards
function withMeasureHost(fn) {
    const host = document.createElement("div");
    host.setAttribute("aria-hidden", "true");
    host.style.cssText =
        "position:absolute;left:-10000px;top:0;visibility:hidden;pointer-events:none;white-space:nowrap;";
    (document.body || document.documentElement).appendChild(host);
    try {
        return fn(host);
    } finally {
        host.remove();
    }
}

// WebGPU adapter details. Browsers may hide, bucket or normalise these, so the
// values describe what the browser chooses to expose, not necessarily the
// physical GPU.
async function getWebGPUInfo() {
    if (!("gpu" in navigator) || !navigator.gpu) return { supported: false };

    const readAdapter = async (options) => {
        let adapter;
        try {
            adapter = await withTimeout(navigator.gpu.requestAdapter(options), 3000, "requestAdapter");
        } catch (e) {
            return { error: String(e) };
        }
        if (!adapter) return null;

        // adapter.info in current browsers; requestAdapterInfo() in older ones
        let info = adapter.info || null;
        if (!info && typeof adapter.requestAdapterInfo === "function") {
            try { info = await withTimeout(adapter.requestAdapterInfo(), 2000, "requestAdapterInfo"); }
            catch (e) { info = null; }
        }

        const limits = {};
        // Limits are prototype getters, so for...in is needed to enumerate them
        for (const key in adapter.limits) {
            const value = adapter.limits[key];
            if (typeof value === "number" || typeof value === "bigint") limits[key] = Number(value);
        }

        return {
            info: info ? {
                vendor: info.vendor ?? null,
                architecture: info.architecture ?? null,
                device: info.device ?? null,
                description: info.description ?? null,
                subgroupMinSize: info.subgroupMinSize ?? null,
                subgroupMaxSize: info.subgroupMaxSize ?? null,
                isFallbackAdapter: info.isFallbackAdapter ?? adapter.isFallbackAdapter ?? null
            } : null,
            features: Array.from(adapter.features || []).sort(),
            limits
        };
    };

    const out = { supported: true };
    out.preferredCanvasFormat = (() => {
        try { return navigator.gpu.getPreferredCanvasFormat(); } catch (e) { return null; }
    })();
    out.wgslLanguageFeatures = (() => {
        try { return Array.from(navigator.gpu.wgslLanguageFeatures || []).sort(); } catch (e) { return null; }
    })();

    out.default = await readAdapter();

    // Multi-GPU machines can expose different adapters per power preference
    const defaultJson = JSON.stringify(out.default);
    out.byPowerPreference = {};
    for (const pref of ["high-performance", "low-power"]) {
        const adapter = await readAdapter({ powerPreference: pref });
        out.byPowerPreference[pref] = JSON.stringify(adapter) === defaultJson
            ? "same as default"
            : adapter;
    }

    return out;
}

// CSS media features. Returns the matching value (or list of values) for each
// feature, null when the browser does not support the feature.
function getMediaFeatures() {
    if (!window.matchMedia) return null;

    const mm = (q) => { try { return window.matchMedia(q); } catch (e) { return null; } };
    const valid = (q) => { const m = mm(q); return !!m && m.media !== "not all"; };
    const matches = (q) => { const m = mm(q); return m ? m.matches : false; };

    // First matching value of a mutually exclusive feature (order matters when one implies another)
    const one = (feature, values) => {
        if (!valid(`(${feature})`)) return null;
        const hit = values.find(v => matches(`(${feature}: ${v})`));
        // Browsers that parse a feature but don't implement it match none of its
        // values (seen in Chromium for inverted-colors, prefers-reduced-data and
        // video-dynamic-range), so that counts as unsupported too
        return hit ?? null;
    };
    // Every matching value (any-pointer, any-hover, color-gamut can match several)
    const all = (feature, values) => {
        if (!valid(`(${feature})`)) return null;
        const hits = values.filter(v => matches(`(${feature}: ${v})`));
        return hits.length ? hits : null;
    };
    // Numeric feature (color bits, color-index entries, monochrome bits) found by binary search
    const level = (feature, cap) => {
        const q = (n) => `(min-${feature}: ${n})`;
        if (!valid(q(0)) || !matches(q(0))) return null;
        if (matches(q(cap))) return `>=${cap}`;
        let lo = 0, hi = cap;
        while (lo < hi) {
            const mid = (lo + hi + 1) >> 1;
            if (matches(q(mid))) lo = mid; else hi = mid - 1;
        }
        return lo;
    };

    return {
        // Display
        colorGamut: all("color-gamut", ["srgb", "p3", "rec2020"]),
        dynamicRange: one("dynamic-range", ["high", "standard"]),
        videoDynamicRange: one("video-dynamic-range", ["high", "standard"]),
        color: level("color", 32),
        colorIndex: level("color-index", 256),
        monochrome: level("monochrome", 32),
        update: one("update", ["fast", "slow", "none"]),

        // Colour and contrast preferences
        prefersColorScheme: one("prefers-color-scheme", ["dark", "light"]),
        prefersReducedMotion: one("prefers-reduced-motion", ["reduce", "no-preference"]),
        prefersReducedTransparency: one("prefers-reduced-transparency", ["reduce", "no-preference"]),
        invertedColors: one("inverted-colors", ["inverted", "none"]),
        prefersContrast: one("prefers-contrast", ["more", "less", "custom", "no-preference"]),
        forcedColors: one("forced-colors", ["active", "none"]),
        prefersReducedData: one("prefers-reduced-data", ["reduce", "no-preference"]),

        // Input devices
        pointer: one("pointer", ["fine", "coarse", "none"]),
        anyPointer: all("any-pointer", ["fine", "coarse", "none"]),
        hover: one("hover", ["hover", "none"]),
        anyHover: all("any-hover", ["hover", "none"]),

        scripting: one("scripting", ["enabled", "initial-only", "none"]),

        // Foldable and dual-screen devices
        horizontalViewportSegments: level("horizontal-viewport-segments", 8),
        verticalViewportSegments: level("vertical-viewport-segments", 8),
        devicePosture: one("device-posture", ["continuous", "folded"]),

        // Vendor-prefixed queries. Chromium doesn't reject unknown vendor queries, so
        // false can mean "unsupported" as well as "doesn't match".
        vendor: Object.fromEntries([
            "(-webkit-transform-3d)", "(-webkit-transform-2d)", "(-webkit-transition)",
            "(-webkit-animation)", "(-webkit-min-device-pixel-ratio: 0)",
            "(-webkit-video-playable-inline)", "(-moz-device-pixel-ratio: 0)",
            "(-moz-touch-enabled)", "(-moz-platform: windows)", "(-moz-platform: macos)",
            "(-moz-platform: linux)", "(-moz-platform: android)", "(-moz-windows-theme: aero)",
            "(-moz-mac-graphite-theme)", "(-ms-high-contrast: active)", "(-ms-high-contrast: none)"
        ].map(q => [q, valid(q) ? matches(q) : null])),

        // Depends on current window state, so excluded from the stable hash
        volatile: {
            orientation: one("orientation", ["portrait", "landscape"]),
            displayMode: one("display-mode", [
                "fullscreen", "standalone", "minimal-ui", "browser",
                "picture-in-picture", "window-controls-overlay"
            ]),
            overflowBlock: one("overflow-block", ["scroll", "paged", "optional-paged", "none"]),
            overflowInline: one("overflow-inline", ["scroll", "none"]),
            navControls: one("nav-controls", ["back", "none"])
        }
    };
}

// JavaScript engine behaviour. Math results, number formatting, typed arrays,
// sort internals, error text and the set of built-ins differ between engines,
// engine versions and sometimes CPUs/OSes. Experimental: results are not
// guaranteed to tell devices apart. Timing is reported separately because it is noisy.
async function getJsEngineInfo() {
    // --- Math: results of transcendental functions ---
    const unary = [
        "acos", "acosh", "asin", "asinh", "atan", "atanh", "cbrt", "cos", "cosh",
        "exp", "expm1", "log", "log1p", "log10", "log2", "sin", "sinh", "sqrt", "tan", "tanh"
    ];
    const inputs = [0.123456789, 0.5, 1.5, Math.E, 10, 1e-7, 12345.6789, -0.75, 1e10, 1e22];
    const math = {};
    for (const name of unary) {
        math[name] = inputs.map(x => fmtNum(Math[name](x))).join(",");
    }
    math.atan2 = [[1, 2], [-3, 0.5], [1e-10, 1e10], [0, -0]]
        .map(([y, x]) => fmtNum(Math.atan2(y, x))).join(",");
    math.pow = [[2, 0.5], [Math.E, 10], [10, -5], [0.1, 0.2], [Math.PI, -100], [1.0000001, 1e7]]
        .map(([b, e]) => fmtNum(Math.pow(b, e))).join(",");
    math.hypot = [[3, 4], [1e200, 1e200], [0.1, 0.2, 0.3]]
        .map(a => fmtNum(Math.hypot(...a))).join(",");
    math.fround = [0.1, 5.05, 1e39, 1.00000001, 16777217]
        .map(x => fmtNum(Math.fround(x))).join(",");

    // --- Floating point and number formatting ---
    const float = {
        add: fmtNum(0.1 + 0.2),
        mul: fmtNum(0.1 * 3),
        div: fmtNum(1 / 3),
        epsilon: fmtNum(Number.EPSILON),
        maxValue: fmtNum(Number.MAX_VALUE),
        minValue: fmtNum(Number.MIN_VALUE),
        denormal: fmtNum(2 ** -1074),
        roundNegZero: Object.is(Math.round(-0.4), -0),
        toString2: (0.1).toString(2),
        toString36: (1 / 3).toString(36),
        toPrecision21: (123.456).toPrecision(21),
        toExponential20: (0.000001234).toExponential(20),
        toFixed20: (1.005).toFixed(20),
        parseFloatLong: fmtNum(parseFloat("0.1000000000000000055511151231257827")),
        bigMul: fmtNum(9007199254740993 * 1.1)
    };

    // --- Typed arrays and binary layout ---
    const typedArrays = {
        endianness: new Uint8Array(new Uint16Array([0x0102]).buffer)[0] === 2 ? "little" : "big",
        float32: Array.from(new Float32Array([0.1, 1 / 3, 1e39, 1e-46, -0, 16777217])).map(fmtNum).join(","),
        float64NaNBytes: Array.from(new Uint8Array(new Float64Array([NaN]).buffer)).join("."),
        float32NaNBits: new Uint32Array(new Float32Array([NaN]).buffer)[0].toString(16),
        clamped: Array.from(new Uint8ClampedArray([0.5, 1.5, 2.5, -3, 300, NaN])).join(","),
        int8Overflow: Array.from(new Int8Array([128, -129, 255, 1e10])).join(","),
        float64Sort: Array.from(new Float64Array([3, NaN, -0, 0, -Infinity, 1]).sort()).map(fmtNum).join(","),
        int32Sort: Array.from(new Int32Array([10, 9, 1, 100, -5]).sort()).join(",")
    };

    // --- Sorting: algorithm-specific comparator call order and tie handling ---
    const calls = [];
    [5, 3, 8, 1, 9, 2, 7, 4, 6, 0, 15, 11, 13, 12, 14, 10].sort((a, b) => {
        calls.push(`${a}>${b}`);
        return a - b;
    });
    const stable = (() => {
        const items = Array.from({ length: 200 }, (_, i) => ({ k: i % 3, i }));
        items.sort((a, b) => a.k - b.k);
        return items.every((x, idx, arr) => idx === 0 || arr[idx - 1].k < x.k || arr[idx - 1].i < x.i);
    })();
    const sorting = {
        comparatorCalls: calls.length,
        comparatorOrderHash: (await hashString(calls.join(" "))).value.slice(0, 16),
        inconsistentComparator: Array.from({ length: 25 }, (_, i) => i)
            .sort((a, b) => (a % 4) - (b % 3)).join(","),
        defaultMixedSort: [10, 9, 1, undefined, null, "b", "a", NaN, -1].sort().map(String).join(","),
        sparseSort: (() => { const a = [, 1, , 0]; a.sort(); return `${a.length}:${Object.keys(a).join("|")}`; })(),
        stable
    };

    // --- Error messages and stack format differ per engine ---
    const msg = (fn) => {
        try { fn(); return null; } catch (e) { return `${e.name}: ${e.message}`; }
    };
    const stack = (() => { try { return String(new Error("x").stack || ""); } catch (e) { return ""; } })();
    const errors = {
        nullProperty: msg(() => { const n = null; return n.x; }),
        undeclaredCall: msg(() => { /* eslint-disable-next-line no-undef */ undeclaredFunctionFp(); }),
        negativeArray: msg(() => new Array(-1)),
        badJson: msg(() => JSON.parse("{bad")),
        toFixedRange: msg(() => (1).toFixed(101)),
        badRegex: msg(() => new RegExp("[")),
        stackStyle: /^\s+at /m.test(stack) ? "at-lines" : (stack.includes("@") ? "at-sign" : "other"),
        captureStackTrace: typeof Error.captureStackTrace,
        stackTraceLimit: typeof Error.stackTraceLimit === "number" ? Error.stackTraceLimit : null
    };

    // --- Which language/runtime features exist (varies by engine version) ---
    const has = (fn) => { try { return !!fn(); } catch (e) { return false; } };
    const features = {
        arrayToSorted: has(() => typeof [].toSorted === "function"),
        arrayFindLast: has(() => typeof [].findLast === "function"),
        arrayFromAsync: has(() => typeof Array.fromAsync === "function"),
        objectGroupBy: has(() => typeof Object.groupBy === "function"),
        promiseWithResolvers: has(() => typeof Promise.withResolvers === "function"),
        setUnion: has(() => typeof Set.prototype.union === "function"),
        iteratorHelpers: has(() => typeof Iterator !== "undefined" && typeof Iterator.prototype.map === "function"),
        stringIsWellFormed: has(() => typeof "".isWellFormed === "function"),
        regexpVFlag: has(() => new RegExp("", "v")),
        intlSegmenter: has(() => typeof Intl.Segmenter === "function"),
        temporal: has(() => typeof Temporal !== "undefined"),
        float16Array: has(() => typeof Float16Array !== "undefined"),
        mathF16round: has(() => typeof Math.f16round === "function"),
        sharedArrayBuffer: has(() => typeof SharedArrayBuffer !== "undefined"),
        atomicsWaitAsync: has(() => typeof Atomics !== "undefined" && typeof Atomics.waitAsync === "function"),
        resizableArrayBuffer: has(() => "resizable" in ArrayBuffer.prototype),
        weakRef: has(() => typeof WeakRef !== "undefined"),
        bigInt64Array: has(() => typeof BigInt64Array !== "undefined")
    };

    // --- Size and shape of built-ins, and native function source text ---
    const builtinsShape = {
        math: Object.getOwnPropertyNames(Math).length,
        arrayPrototype: Object.getOwnPropertyNames(Array.prototype).length,
        stringPrototype: Object.getOwnPropertyNames(String.prototype).length,
        objectStatic: Object.getOwnPropertyNames(Object).length,
        reflect: Object.getOwnPropertyNames(Reflect).length,
        number: Object.getOwnPropertyNames(Number).length,
        intl: Object.getOwnPropertyNames(Intl).length,
        nativeFunctionText: String(Math.sin),
        evalSourceLength: String(eval).length
    };

    // Deterministic part is hashed; timing is not included because it is noisy
    const hash = await hashString(JSON.stringify({ math, float, typedArrays, sorting, errors, features, builtinsShape }));

    const t0 = performance.now();
    let acc = 0;
    for (let i = 0; i < 200000; i++) acc += Math.sin(i) * Math.cos(i);
    const mathLoopMs = performance.now() - t0;

    return {
        hashAlgorithm: hash.algorithm,
        hash: hash.value,
        math, float, typedArrays, sorting, errors, features, builtinsShape,
        timing: {
            noisy: true,
            note: "Excluded from the combined hash. Depends on CPU load and timer precision.",
            mathLoopMs: Number(mathLoopMs.toFixed(2)),
            sink: acc === 123.456
        }
    };
}

// Text rendering: canvas metrics, DOM boxes, SVG text, emoji and subpixel behaviour.
// Font availability and actual rendering are different things, so this measures
// what the engine does with text rather than just which fonts exist.
const TEXT_SAMPLES = {
    latin: "mmmmmmmmmmlli WwQ@#0123456789",
    pangram: "Cwm fjord bank glyphs vext quiz",
    cjk: "日本語の文字中文한국어",
    arabic: "مرحبا بالعالم",
    emoji: "😀🫠🧑‍🚀🏳️‍🌈👍🏽"
};
const TEXT_FONTS = [
    "monospace", "sans-serif", "serif", "system-ui", "cursive", "fantasy",
    "Arial", "Times New Roman", "Courier New", "Segoe UI", "Helvetica Neue",
    "Noto Sans", "Roboto", "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji"
];
const GENERIC_FAMILIES = ["monospace", "sans-serif", "serif", "system-ui", "cursive", "fantasy"];
const EMOJI_STACK = '"Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif';

async function getTextRenderingInfo() {
    const r4 = (n) => (typeof n === "number" && Number.isFinite(n) ? Number(n.toFixed(4)) : null);
    const part = async (fn) => { try { return await fn(); } catch (e) { return { error: String(e) }; } };

    // Canvas measureText(): advance width plus bounding boxes and font ascent/descent
    const canvasMetrics = await part(() => {
        const ctx = document.createElement("canvas").getContext("2d");
        const out = {};
        for (const font of TEXT_FONTS) {
            out[font] = {};
            // Generic families must not be quoted; named fonts fall back to sans-serif
            ctx.font = GENERIC_FAMILIES.includes(font)
                ? `72px ${font}`
                : `72px "${font}", sans-serif`;
            for (const [name, text] of Object.entries(TEXT_SAMPLES)) {
                const m = ctx.measureText(text);
                // width, bbox left/right/ascent/descent, font ascent/descent
                out[font][name] = [
                    m.width, m.actualBoundingBoxLeft, m.actualBoundingBoxRight,
                    m.actualBoundingBoxAscent, m.actualBoundingBoxDescent,
                    m.fontBoundingBoxAscent, m.fontBoundingBoxDescent
                ].map(r4).join(",");
            }
        }
        out._columns = "width,bboxLeft,bboxRight,bboxAscent,bboxDescent,fontAscent,fontDescent";
        return out;
    });

    // Which canvas text properties this browser implements
    const canvasTextFeatures = await part(() => {
        const ctx = document.createElement("canvas").getContext("2d");
        return {
            letterSpacing: "letterSpacing" in ctx,
            wordSpacing: "wordSpacing" in ctx,
            fontKerning: "fontKerning" in ctx,
            fontStretch: "fontStretch" in ctx,
            fontVariantCaps: "fontVariantCaps" in ctx,
            textRendering: "textRendering" in ctx,
            textAlign: ctx.textAlign,
            textBaseline: ctx.textBaseline,
            direction: ctx.direction,
            defaultFont: ctx.font
        };
    });

    // DOM layout: line box, ascent/descent via a baseline probe, fractional widths
    const dom = await part(() => withMeasureHost((host) => {
        const out = { fonts: {} };
        for (const font of ["monospace", "sans-serif", "serif", "system-ui", "Arial", "Times New Roman", "Courier New"]) {
            const family = GENERIC_FAMILIES.includes(font) ? font : `"${font}", sans-serif`;
            const span = document.createElement("span");
            span.style.cssText = `font:100px/normal ${family};`;
            span.textContent = "Hxgjpq|";
            const probe = document.createElement("span");
            probe.style.cssText = "display:inline-block;width:0;height:0;";
            span.appendChild(probe);
            host.appendChild(span);
            const s = span.getBoundingClientRect();
            const p = probe.getBoundingClientRect();
            const ascent = p.top - s.top; // probe sits on the baseline
            out.fonts[font] = {
                width: r4(s.width),
                height: r4(s.height),
                ascent: r4(ascent),
                descent: r4(s.height - ascent)
            };
        }

        // Fractional text widths, and whole-string width vs sum of single characters
        const frac = document.createElement("span");
        frac.style.cssText = "font:13.37px sans-serif;letter-spacing:0.1px;";
        frac.textContent = TEXT_SAMPLES.latin;
        host.appendChild(frac);
        const fw = frac.getBoundingClientRect().width;

        const whole = document.createElement("span");
        whole.style.cssText = "font:11px sans-serif;";
        whole.textContent = "iiiiiiiiiiWWWWWWWWWW";
        host.appendChild(whole);
        let perChar = 0;
        for (const ch of "iiiiiiiiiiWWWWWWWWWW") {
            const c = document.createElement("span");
            c.style.cssText = "font:11px sans-serif;display:inline-block;";
            c.textContent = ch;
            host.appendChild(c);
            perChar += c.getBoundingClientRect().width;
        }
        out.fractionalWidth = r4(fw);
        out.fractionalLayout = Math.abs(fw - Math.round(fw)) > 0.001;
        out.wholeStringWidth = r4(whole.getBoundingClientRect().width);
        out.sumOfCharacterWidths = r4(perChar);

        // Range boxes for emoji and mixed-script text
        try {
            out.ranges = {};
            for (const [name, text] of Object.entries(TEXT_SAMPLES)) {
                const el = document.createElement("span");
                el.style.cssText = `font:32px ${EMOJI_STACK};`;
                el.textContent = text;
                host.appendChild(el);
                const range = document.createRange();
                range.selectNodeContents(el);
                const b = range.getBoundingClientRect();
                out.ranges[name] = `${r4(b.width)}x${r4(b.height)} rects=${range.getClientRects().length}`;
            }
        } catch (e) {
            out.ranges = { error: String(e) };
        }
        return out;
    }));

    // SVG text metrics
    const svg = await part(() => withMeasureHost((host) => {
        const NS = "http://www.w3.org/2000/svg";
        const root = document.createElementNS(NS, "svg");
        root.setAttribute("width", "600");
        root.setAttribute("height", "200");
        host.appendChild(root);
        const out = {};
        for (const font of ["monospace", "sans-serif", "serif", "Arial", "Times New Roman"]) {
            const t = document.createElementNS(NS, "text");
            t.setAttribute("x", "10");
            t.setAttribute("y", "60");
            t.setAttribute("font-size", "48");
            t.setAttribute("font-family", font);
            t.textContent = "Fingerprint Wjg";
            root.appendChild(t);
            const b = t.getBBox();
            out[font] = {
                bbox: [b.x, b.y, b.width, b.height].map(r4).join(","),
                computedTextLength: r4(t.getComputedTextLength()),
                subStringLength: r4(t.getSubStringLength(0, 5)),
                chars: t.getNumberOfChars(),
                secondCharStart: (() => { const p = t.getStartPositionOfChar(1); return `${r4(p.x)},${r4(p.y)}`; })(),
                firstCharExtent: (() => { const e = t.getExtentOfChar(0); return [e.x, e.y, e.width, e.height].map(r4).join(","); })()
            };
        }
        return out;
    }));

    // Emoji: rendered pixel bounds, colour, hash, and ZWJ/modifier ligature support
    const emoji = await part(async () => {
        const samples = ["😀", "🫠", "🫨", "🫩", "🧑‍🚀", "🏳️‍🌈", "🇬🇪", "👍🏽"];
        const canvas = document.createElement("canvas");
        canvas.width = 96;
        canvas.height = 64;
        const ctx = canvas.getContext("2d", { willReadFrequently: true });
        const out = { glyphs: {} };
        for (const e of samples) {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.font = `40px ${EMOJI_STACK}`;
            ctx.textBaseline = "top";
            ctx.fillText(e, 4, 4);
            const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
            let minX = width, minY = height, maxX = -1, maxY = -1, colorful = false;
            for (let y = 0; y < height; y++) {
                for (let x = 0; x < width; x++) {
                    const i = (y * width + x) * 4;
                    if (data[i + 3] === 0) continue;
                    if (x < minX) minX = x;
                    if (x > maxX) maxX = x;
                    if (y < minY) minY = y;
                    if (y > maxY) maxY = y;
                    const hi = Math.max(data[i], data[i + 1], data[i + 2]);
                    const lo = Math.min(data[i], data[i + 1], data[i + 2]);
                    if (hi - lo > 24) colorful = true;
                }
            }
            const hash = await hashString(canvas.toDataURL());
            out.glyphs[e] = {
                width: r4(ctx.measureText(e).width),
                drawnBounds: maxX < 0 ? null : `${maxX - minX + 1}x${maxY - minY + 1}`,
                colorful,
                hash: hash.value.slice(0, 16)
            };
        }
        const w = (s) => ctx.measureText(s).width;
        ctx.font = `40px ${EMOJI_STACK}`;
        out.zwjLigatures = {
            astronaut: w("🧑‍🚀") < w("🧑") + w("🚀") - 0.5,
            rainbowFlag: w("🏳️‍🌈") < w("🏳") + w("🌈") - 0.5,
            skinToneModifier: w("👍🏽") < w("👍") + w("🏽") - 0.5
        };
        return out;
    });

    // Subpixel positioning and anti-aliasing mode
    const subpixel = await part(async () => {
        const hashes = [];
        for (const dx of [0, 0.25, 0.5, 0.75]) {
            const c = document.createElement("canvas");
            c.width = 160;
            c.height = 30;
            const ctx = c.getContext("2d");
            ctx.font = "15px sans-serif";
            ctx.fillText("Subpixel text", 4 + dx, 20);
            hashes.push((await hashString(c.toDataURL())).value.slice(0, 12));
        }

        // Opaque canvas with black-on-white text: coloured fringes mean LCD anti-aliasing
        const lc = document.createElement("canvas");
        lc.width = 160;
        lc.height = 40;
        const lctx = lc.getContext("2d", { alpha: false, willReadFrequently: true });
        lctx.fillStyle = "#fff";
        lctx.fillRect(0, 0, lc.width, lc.height);
        lctx.fillStyle = "#000";
        lctx.font = "20px sans-serif";
        lctx.fillText("Subpixel LCD", 4, 28);
        const px = lctx.getImageData(0, 0, lc.width, lc.height).data;
        let coloured = false;
        for (let i = 0; i < px.length; i += 4) {
            if (px[i] !== px[i + 1] || px[i + 1] !== px[i + 2]) { coloured = true; break; }
        }

        return {
            canvasOffsetHashes: hashes,
            distinctRenderings: new Set(hashes).size,
            canvasSubpixelPositioning: new Set(hashes).size > 1,
            lcdAntialiasing: coloured
        };
    });

    const hash = await hashString(JSON.stringify({ canvasMetrics, canvasTextFeatures, dom, svg, emoji, subpixel }));

    return {
        hashAlgorithm: hash.algorithm,
        hash: hash.value,
        canvasMetrics, canvasTextFeatures, dom, svg, emoji, subpixel
    };
}

// ---------------------------------------------------------------------------
// H. WebGPU rendering, CSS feature support
// ---------------------------------------------------------------------------

const WEBGPU_RENDER_SHADER = `
struct VOut {
    @builtin(position) pos: vec4f,
    @location(0) uv: vec2f,
    @location(1) col: vec3f,
};

@vertex
fn vs(@builtin(vertex_index) i: u32) -> VOut {
    var p = array<vec2f, 6>(
        vec2f(-0.9, -0.8), vec2f(0.8, -0.9), vec2f(0.1, 0.9),
        vec2f(-0.7, 0.6), vec2f(0.9, 0.2), vec2f(0.3, -0.7)
    );
    var c = array<vec3f, 6>(
        vec3f(1.0, 0.2, 0.1), vec3f(0.1, 0.9, 0.3), vec3f(0.2, 0.3, 1.0),
        vec3f(0.9, 0.8, 0.1), vec3f(0.6, 0.1, 0.9), vec3f(0.1, 0.8, 0.8)
    );
    var o: VOut;
    o.pos = vec4f(p[i], 0.0, 1.0);
    o.uv = p[i];
    o.col = c[i];
    return o;
}

@fragment
fn fs(in: VOut) -> @location(0) vec4f {
    let t = in.uv * 23.0;
    // Transcendental functions: results can differ slightly between GPUs and drivers
    let w = sin(t.x) * cos(t.y)
        + exp(-dot(in.uv, in.uv) * 3.0)
        + pow(abs(in.uv.x) + 0.1, 2.2)
        + tanh(t.x * 0.1)
        + atan2(in.uv.y, in.uv.x + 0.5)
        + log(1.5 + in.uv.y);
    let n = fract(sin(dot(in.uv, vec2f(12.9898, 78.233))) * 43758.5453);
    let c = in.col * (0.55 + 0.45 * sin(w * 3.0)) + vec3f(n * 0.08);
    return vec4f(c, 0.85);
}
`;

const WEBGPU_COMPUTE_SHADER = `
@group(0) @binding(0) var<storage, read_write> out: array<f32>;

@compute @workgroup_size(16)
fn main(@builtin(global_invocation_id) id: vec3u) {
    let i = id.x;
    let k = i / 16u;
    let x = f32(i % 16u) * 0.731 + 0.123;
    var r = 0.0;
    if (k == 0u) { r = sin(x * 10.0); }
    else if (k == 1u) { r = cos(x * 10.0); }
    else if (k == 2u) { r = exp(x); }
    else if (k == 3u) { r = log(x); }
    else if (k == 4u) { r = pow(x, 1.7); }
    else if (k == 5u) { r = tanh(x); }
    else if (k == 6u) { r = atan2(x, 0.5 + x * 0.1); }
    else { r = inverseSqrt(x) + fma(x, x, 0.1); }
    out[i] = r;
}
`;

// Draws a 4x MSAA scene to an offscreen texture, reads the pixels back and hashes
// them, then runs a compute shader of math functions and hashes its float bits.
// No canvas is attached to the page. Different GPUs, drivers and software
// rasterizers can differ in blending, MSAA resolve and transcendental maths.
async function getWebGPURendering() {
    if (!("gpu" in navigator) || !navigator.gpu) return { supported: false };

    let device = null;
    try {
        const adapter = await withTimeout(navigator.gpu.requestAdapter(), 3000, "requestAdapter");
        if (!adapter) return { supported: true, adapter: null };
        device = await withTimeout(adapter.requestDevice(), 3000, "requestDevice");

        device.pushErrorScope("validation");
        const out = { supported: true };
        out.render = await part(() => renderWebGPUScene(device));
        out.compute = await part(() => computeWebGPUMath(device));
        const err = await device.popErrorScope();
        out.validationError = err ? err.message : null;

        const hash = await hashString(JSON.stringify({
            render: out.render && out.render.hash,
            compute: out.compute && out.compute.hash
        }));
        out.hashAlgorithm = hash.algorithm;
        out.hash = hash.value;
        return out;
    } catch (e) {
        return { supported: true, error: String(e) };
    } finally {
        try { if (device) device.destroy(); } catch (e) { /* ignore */ }
    }

    async function part(fn) {
        try { return await fn(); } catch (e) { return { error: String(e) }; }
    }
}

async function renderWebGPUScene(device) {
    const W = 128, H = 128, SAMPLES = 4, FORMAT = "rgba8unorm";
    const module = device.createShaderModule({ code: WEBGPU_RENDER_SHADER });
    const pipeline = device.createRenderPipeline({
        layout: "auto",
        vertex: { module, entryPoint: "vs" },
        fragment: {
            module,
            entryPoint: "fs",
            targets: [{
                format: FORMAT,
                blend: {
                    color: { srcFactor: "src-alpha", dstFactor: "one-minus-src-alpha" },
                    alpha: { srcFactor: "one", dstFactor: "one-minus-src-alpha" }
                }
            }]
        },
        primitive: { topology: "triangle-list" },
        multisample: { count: SAMPLES }
    });

    const msaa = device.createTexture({
        size: [W, H], format: FORMAT, sampleCount: SAMPLES,
        usage: GPUTextureUsage.RENDER_ATTACHMENT
    });
    const resolve = device.createTexture({
        size: [W, H], format: FORMAT,
        usage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.COPY_SRC
    });
    const readback = device.createBuffer({
        size: W * H * 4, // W * 4 = 512 bytes per row, a multiple of the required 256
        usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ
    });

    const encoder = device.createCommandEncoder();
    const pass = encoder.beginRenderPass({
        colorAttachments: [{
            view: msaa.createView(),
            resolveTarget: resolve.createView(),
            clearValue: { r: 0.1, g: 0.2, b: 0.3, a: 1 },
            loadOp: "clear",
            storeOp: "discard"
        }]
    });
    pass.setPipeline(pipeline);
    pass.draw(6);
    pass.end();
    encoder.copyTextureToBuffer({ texture: resolve }, { buffer: readback, bytesPerRow: W * 4 }, [W, H]);
    device.queue.submit([encoder.finish()]);

    await withTimeout(readback.mapAsync(GPUMapMode.READ), 5000, "mapAsync");
    const pixels = new Uint8Array(readback.getMappedRange().slice(0));
    readback.unmap();

    const colors = new Set(new Uint32Array(pixels.buffer));
    const hash = await hashBytes(pixels);
    [msaa, resolve, readback].forEach(r => { try { r.destroy(); } catch (e) { /* ignore */ } });

    return {
        hashAlgorithm: hash.algorithm,
        hash: hash.value,
        width: W,
        height: H,
        sampleCount: SAMPLES,
        format: FORMAT,
        distinctColors: colors.size,
        first4Pixels: Array.from(pixels.slice(0, 16))
    };
}

async function computeWebGPUMath(device) {
    const COUNT = 128;
    const module = device.createShaderModule({ code: WEBGPU_COMPUTE_SHADER });
    const pipeline = device.createComputePipeline({ layout: "auto", compute: { module, entryPoint: "main" } });

    const storage = device.createBuffer({
        size: COUNT * 4,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC
    });
    const readback = device.createBuffer({
        size: COUNT * 4,
        usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ
    });
    const group = device.createBindGroup({
        layout: pipeline.getBindGroupLayout(0),
        entries: [{ binding: 0, resource: { buffer: storage } }]
    });

    const encoder = device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, group);
    pass.dispatchWorkgroups(COUNT / 16);
    pass.end();
    encoder.copyBufferToBuffer(storage, 0, readback, 0, COUNT * 4);
    device.queue.submit([encoder.finish()]);

    await withTimeout(readback.mapAsync(GPUMapMode.READ), 5000, "mapAsync");
    const floats = new Float32Array(readback.getMappedRange().slice(0));
    readback.unmap();

    // Hash the exact bit patterns so tiny differences are not hidden by formatting
    const bits = new Uint8Array(floats.buffer.slice(0));
    const hash = await hashBytes(bits);
    [storage, readback].forEach(r => { try { r.destroy(); } catch (e) { /* ignore */ } });

    return {
        hashAlgorithm: hash.algorithm,
        hash: hash.value,
        count: COUNT,
        functions: ["sin", "cos", "exp", "log", "pow", "tanh", "atan2", "inverseSqrt+fma"],
        firstOfEachFunction: Array.from({ length: 8 }, (_, k) => fmtNum(floats[k * 16]))
    };
}

// CSS capabilities. Each probe is a feature a browser either has or doesn't,
// and the pattern of yes/no answers is tied to the engine and its version.
const CSS_PROPERTY_PROBES = [
    ["display", "grid"], ["display", "contents"], ["display", "flow-root"],
    ["grid-template-columns", "subgrid"], ["aspect-ratio", "1 / 1"], ["gap", "1px"],
    ["container-type", "inline-size"], ["backdrop-filter", "blur(1px)"],
    ["-webkit-backdrop-filter", "blur(1px)"], ["color", "oklch(50% 0.1 120)"],
    ["color", "lab(50% 10 10)"], ["color", "color-mix(in srgb, red, blue)"],
    ["color", "light-dark(red, blue)"], ["color", "rgb(from red r g b)"],
    ["color", "color(display-p3 1 0 0)"], ["width", "min(1px, 2px)"],
    ["width", "clamp(1px, 2px, 3px)"], ["width", "calc(1px * sin(1))"],
    ["width", "100dvh"], ["height", "100svh"], ["width", "1cqw"],
    ["text-wrap", "balance"], ["text-wrap", "pretty"], ["scrollbar-gutter", "stable"],
    ["scrollbar-width", "thin"], ["scrollbar-color", "red blue"],
    ["overscroll-behavior", "contain"], ["field-sizing", "content"],
    ["anchor-name", "--a"], ["position-anchor", "--a"],
    ["interpolate-size", "allow-keywords"], ["animation-timeline", "scroll()"],
    ["view-transition-name", "a"], ["transition-behavior", "allow-discrete"],
    ["content-visibility", "auto"], ["contain", "layout"], ["accent-color", "red"],
    ["appearance", "none"], ["-webkit-appearance", "none"], ["-moz-appearance", "none"],
    ["mask-image", "linear-gradient(red, blue)"], ["-webkit-mask-image", "linear-gradient(red, blue)"],
    ["clip-path", "circle(50%)"], ["offset-path", "path('M0 0')"],
    ["translate", "1px"], ["rotate", "1deg"], ["scale", "1"], ["zoom", "1"],
    ["font-variation-settings", "'wght' 400"], ["font-optical-sizing", "auto"],
    ["font-palette", "normal"], ["font-synthesis-weight", "none"],
    ["text-decoration-thickness", "1px"], ["text-underline-offset", "1px"],
    ["text-emphasis", "dot"], ["hyphens", "auto"], ["line-clamp", "2"],
    ["-webkit-line-clamp", "2"], ["initial-letter", "2"], ["math-style", "compact"],
    ["inset", "0"], ["margin-inline", "1px"], ["padding-block", "1px"],
    ["border-start-start-radius", "1px"], ["object-fit", "cover"],
    ["image-rendering", "pixelated"], ["image-rendering", "crisp-edges"],
    ["background", "image-set(url(a.png) 1x)"], ["shape-outside", "circle()"],
    ["touch-action", "pan-x"], ["will-change", "transform"], ["isolation", "isolate"],
    ["mix-blend-mode", "multiply"], ["filter", "drop-shadow(0 0 1px red)"],
    ["backface-visibility", "hidden"], ["transform-style", "preserve-3d"],
    ["perspective", "100px"], ["scroll-snap-type", "x mandatory"],
    ["scroll-timeline", "--t"], ["caret-color", "red"], ["color-scheme", "light dark"],
    ["forced-color-adjust", "none"], ["print-color-adjust", "exact"],
    ["-webkit-text-stroke", "1px red"], ["-webkit-font-smoothing", "antialiased"],
    ["-moz-osx-font-smoothing", "grayscale"], ["-webkit-tap-highlight-color", "red"],
    ["-webkit-touch-callout", "none"], ["-moz-user-select", "none"],
    ["-webkit-box-reflect", "below"], ["reading-flow", "normal"],
    ["text-box-trim", "trim-both"], ["corner-shape", "squircle"]
];

const CSS_SELECTOR_PROBES = [
    ":has(a)", ":is(a, b)", ":where(a)", ":not(a, b)", ":focus-visible", ":focus-within",
    ":user-invalid", ":modal", ":popover-open", ":fullscreen", "::backdrop", "::marker",
    "::file-selector-button", "::highlight(a)", "::view-transition", ":state(a)",
    ":autofill", ":-webkit-autofill", ":-moz-focusring", "::-webkit-scrollbar",
    "::-moz-selection", ":nth-child(1 of a)", ":dir(ltr)", ":lang(en)",
    ":placeholder-shown", "::target-text", ":open", "::details-content", "& a",
    "::slotted(a)", ":host", ":defined", ":picture-in-picture", ":seeking", ":muted"
];

const CSS_AT_RULE_PROBES = [
    "@container", "@layer", "@scope", "@starting-style", "@property", "@font-palette-values",
    "@view-transition", "@position-try", "@counter-style", "@font-feature-values", "@page"
];

const CSS_FONT_PROBES = [
    "font-tech(color-COLRv1)", "font-tech(variations)", "font-tech(palettes)",
    "font-format(woff2)", "font-format(woff)", "font-format(opentype)", "font-format(collection)"
];

const CSS_API_PROBES = {
    "CSS.registerProperty": () => typeof CSS.registerProperty === "function",
    "CSS.highlights": () => !!CSS.highlights,
    "CSS.paintWorklet": () => !!CSS.paintWorklet,
    "CSS.escape": () => typeof CSS.escape === "function",
    "CSS.px (Typed OM)": () => typeof CSS.px === "function",
    "CSSStyleSheet.replaceSync": () => typeof CSSStyleSheet.prototype.replaceSync === "function",
    "document.adoptedStyleSheets": () => "adoptedStyleSheets" in document,
    "Element.checkVisibility": () => typeof Element.prototype.checkVisibility === "function",
    "document.startViewTransition": () => typeof document.startViewTransition === "function",
    "HTMLElement.showPopover": () => typeof HTMLElement.prototype.showPopover === "function",
    "Highlight": () => typeof Highlight !== "undefined",
    "ScrollTimeline": () => typeof ScrollTimeline !== "undefined",
    "ViewTimeline": () => typeof ViewTimeline !== "undefined",
    "StylePropertyMap": () => typeof StylePropertyMap !== "undefined",
    "CSSContainerRule": () => typeof CSSContainerRule !== "undefined",
    "CSSLayerBlockRule": () => typeof CSSLayerBlockRule !== "undefined",
    "CSSScopeRule": () => typeof CSSScopeRule !== "undefined",
    "CSSStartingStyleRule": () => typeof CSSStartingStyleRule !== "undefined",
    "CSSPropertyRule": () => typeof CSSPropertyRule !== "undefined",
    "CSSFontPaletteValuesRule": () => typeof CSSFontPaletteValuesRule !== "undefined",
    "CSSPositionTryRule": () => typeof CSSPositionTryRule !== "undefined",
    "CSSNestedDeclarations": () => typeof CSSNestedDeclarations !== "undefined",
    "ResizeObserver contentBoxSize": () => typeof ResizeObserverEntry !== "undefined" && "contentBoxSize" in ResizeObserverEntry.prototype
};

const SYSTEM_COLOR_KEYWORDS = [
    "Canvas", "CanvasText", "LinkText", "VisitedText", "ActiveText", "ButtonFace", "ButtonText",
    "ButtonBorder", "Field", "FieldText", "Highlight", "HighlightText", "SelectedItem",
    "SelectedItemText", "Mark", "MarkText", "GrayText", "AccentColor", "AccentColorText",
    "ActiveBorder", "ActiveCaption", "AppWorkspace", "Background", "ButtonHighlight",
    "ButtonShadow", "CaptionText", "InactiveBorder", "InactiveCaption", "InactiveCaptionText",
    "InfoBackground", "InfoText", "Menu", "MenuText", "Scrollbar", "ThreeDDarkShadow",
    "ThreeDFace", "ThreeDHighlight", "ThreeDLightShadow", "ThreeDShadow", "Window",
    "WindowFrame", "WindowText", "-webkit-focus-ring-color"
];

const SYSTEM_FONT_KEYWORDS = ["caption", "icon", "menu", "message-box", "small-caption", "status-bar", "-apple-system-body"];

async function getCssFeatures() {
    if (!window.CSS || typeof CSS.supports !== "function") return { supported: false };

    const test = (fn) => { try { return !!fn(); } catch (e) { return false; } };
    const results = {};

    const unsupported = { properties: [], selectors: [], atRules: [], fonts: [], apis: [] };
    const bits = [];
    const record = (group, label, ok) => {
        bits.push(ok ? "1" : "0");
        if (!ok) unsupported[group].push(label);
    };

    for (const [prop, value] of CSS_PROPERTY_PROBES) {
        record("properties", `${prop}: ${value}`, test(() => CSS.supports(prop, value)));
    }
    for (const sel of CSS_SELECTOR_PROBES) {
        record("selectors", sel, test(() => CSS.supports(`selector(${sel})`)));
    }
    for (const rule of CSS_AT_RULE_PROBES) {
        // at-rule() is itself new, so a false here can mean "can't ask" rather than "no"
        record("atRules", rule, test(() => CSS.supports(`at-rule(${rule})`)));
    }
    for (const font of CSS_FONT_PROBES) {
        record("fonts", font, test(() => CSS.supports(font)));
    }
    for (const [name, fn] of Object.entries(CSS_API_PROBES)) {
        record("apis", name, test(fn));
    }

    results.tested = bits.length;
    results.supportedCount = bits.filter(b => b === "1").length;
    results.unsupported = unsupported;
    results.bitmapHash = (await hashString(bits.join(""))).value.slice(0, 16);

    // Values that depend on the OS, theme and browser defaults rather than on support
    results.computed = withMeasureHost((host) => {
        const out = {};
        const cs = getComputedStyle(document.documentElement);
        const names = [];
        for (let i = 0; i < cs.length; i++) names.push(cs[i]);
        out.computedPropertyCount = cs.length;
        out.computedPropertyNames = names;

        // System colour keywords resolve differently per OS and theme
        const colorEl = document.createElement("div");
        host.appendChild(colorEl);
        out.systemColors = {};
        for (const kw of SYSTEM_COLOR_KEYWORDS) {
            if (!test(() => CSS.supports("color", kw))) { out.systemColors[kw] = null; continue; }
            colorEl.style.color = kw;
            out.systemColors[kw] = getComputedStyle(colorEl).color;
        }

        // System fonts from the `font` shorthand resolve to OS-specific families and sizes
        out.systemFonts = {};
        for (const kw of SYSTEM_FONT_KEYWORDS) {
            const el = document.createElement("div");
            host.appendChild(el);
            el.style.font = kw;
            const c = getComputedStyle(el);
            out.systemFonts[kw] = el.style.font
                ? `${c.fontFamily} | ${c.fontSize} | ${c.fontWeight} | ${c.fontStyle}`
                : null;
        }

        // Default sizes for generic families (e.g. monospace is often 13px)
        out.defaultFontSizes = {};
        for (const fam of ["serif", "sans-serif", "monospace", "system-ui", "cursive", "fantasy"]) {
            const el = document.createElement("div");
            el.style.cssText = `font-family:${fam};font-size:medium;`;
            host.appendChild(el);
            out.defaultFontSizes[fam] = getComputedStyle(el).fontSize;
        }

        // Classic scrollbar width (0 for overlay scrollbars)
        const sb = document.createElement("div");
        sb.style.cssText = "width:100px;height:100px;overflow:scroll;";
        host.appendChild(sb);
        out.scrollbarWidth = sb.offsetWidth - sb.clientWidth;
        out.scrollbarHeight = sb.offsetHeight - sb.clientHeight;
        return out;
    });

    // Hash everything except the (long) property-name list, which is hashed separately
    const nameList = results.computed.computedPropertyNames || [];
    results.computed.computedPropertyNamesHash = (await hashString(nameList.join(","))).value.slice(0, 16);
    delete results.computed.computedPropertyNames;

    const hash = await hashString(JSON.stringify(results));
    return { hashAlgorithm: hash.algorithm, hash: hash.value, ...results };
}

// ---------------------------------------------------------------------------
// I. Test harness: statuses, canonical serialization, categories, correlation
// ---------------------------------------------------------------------------

// Every test registered below ends in exactly one of four states:
//   success      the test ran and produced measurements
//   unsupported  the browser does not implement the API at all
//   unavailable  the API exists but cannot be used here (blocked by policy, needs a
//                secure context / permission / cross-origin isolation, or no hardware)
//   failed       the test threw, timed out or gave an inconsistent result
// Nothing in here records how long anything took: timing is never a matching signal.
class TestSignal extends Error {
    constructor(status, reason) {
        super(reason);
        this.name = "TestSignal";
        this.status = status;
        this.reason = reason;
    }
}
const unsupported = (reason) => { throw new TestSignal("unsupported", reason); };
const unavailable = (reason) => { throw new TestSignal("unavailable", reason); };

// Browsers report policy and permission blocks with these error names
const BLOCKED_ERRORS = new Set(["SecurityError", "NotAllowedError"]);

function classifyError(e) {
    if (e instanceof TestSignal) return { status: e.status, reason: e.reason, error: null };
    if (e && BLOCKED_ERRORS.has(e.name)) {
        return { status: "unavailable", reason: `blocked: ${e.name}`, error: String(e) };
    }
    const timedOut = /timed out/.test(String((e && e.message) || ""));
    return { status: "failed", reason: timedOut ? "timeout" : "exception", error: String(e) };
}

// Sub-measurements inside one test use the same status vocabulary (no hashing).
// fn must return a plain object; its fields are merged into { status: "success" }.
async function runSub(fn) {
    try {
        return { status: "success", ...(await fn()) };
    } catch (e) {
        const c = classifyError(e);
        return { status: c.status, reason: c.reason, error: c.error };
    }
}

// Canonical serialization for hashing. Unlike JSON.stringify it sorts object keys,
// keeps -0 / NaN / Infinity / BigInt distinct instead of turning them into 0 / null,
// and drops undefined and function values. Same value in, same text out.
function stableStringify(value) {
    const enc = (v) => {
        if (v === null || v === undefined) return "null";
        switch (typeof v) {
            case "number": return Number.isFinite(v) ? fmtNum(v) : String(v);
            case "bigint": return `${v}n`;
            case "boolean": return v ? "true" : "false";
            case "string": return JSON.stringify(v);
            case "function": case "symbol": return "null";
        }
        if (ArrayBuffer.isView(v) && !(v instanceof DataView)) {
            return `${v.constructor.name}[${Array.from(v, enc).join(",")}]`;
        }
        if (Array.isArray(v)) return `[${v.map(enc).join(",")}]`;
        if (v instanceof Date) return JSON.stringify(v.toISOString());
        if (v instanceof Set) return `Set[${Array.from(v, enc).sort().join(",")}]`;
        if (v instanceof Map) {
            return `Map{${Array.from(v, ([k, x]) => `${enc(k)}:${enc(x)}`).sort().join(",")}}`;
        }
        const keys = Object.keys(v)
            .filter((k) => v[k] !== undefined && typeof v[k] !== "function")
            .sort();
        return `{${keys.map((k) => `${JSON.stringify(k)}:${enc(v[k])}`).join(",")}}`;
    };
    return enc(value);
}

async function hashValue(value) {
    return hashString(stableStringify(value));
}

// Rounds to a fixed number of decimals so tiny float noise does not split a bucket
const roundTo = (n, digits = 4) =>
    typeof n === "number" && Number.isFinite(n) ? Number(n.toFixed(digits)) : null;

// Tests register themselves here when their script loads. fingerprint-lib.js must be
// loaded first. Fields:
//   id        key under result.tests
//   category  "static" | "configuration" | "behavioral"
//   groups    correlation groups this test belongs to (see FP_CORRELATION_GROUPS)
//   run       async (ctx) => { raw, normalized, hashes?, notes? }, ctx = { result, opts }
//   optIn     optional name of an option that must be true (permission prompts)
//   timeoutMs optional, default 10000
const FP_TEST_REGISTRY = [];
const registerTest = (test) => { FP_TEST_REGISTRY.push(test); };

/**
 * A test's run() returns:
 *   raw        everything measured, including diagnostics and volatile values
 *   normalized only the stable part: sorted, bucketed or quantized. This is what is hashed.
 *   hashes     optional { name: value } of extra named hashes (kept separate on purpose,
 *              e.g. supported / smooth / powerEfficient)
 *   notes      optional strings explaining caveats
 */
async function runRegisteredTest(test, ctx) {
    const base = { id: test.id, category: test.category, groups: test.groups || [] };
    if (test.optIn && !ctx.opts[test.optIn]) {
        return {
            ...base, status: "unavailable", reason: `opt-in required (${test.optIn})`, error: null,
            raw: null, normalized: null, hashAlgorithm: null, hash: null
        };
    }
    try {
        const out = await withTimeout(Promise.resolve().then(() => test.run(ctx)), test.timeoutMs || 10000, test.id);
        const normalized = out.normalized === undefined ? null : out.normalized;
        const hash = await hashValue(normalized);
        const entry = {
            ...base, status: "success", reason: null, error: null,
            raw: out.raw === undefined ? null : out.raw,
            normalized,
            hashAlgorithm: hash.algorithm,
            hash: hash.value
        };
        if (out.hashes) {
            entry.hashes = {};
            for (const [name, v] of Object.entries(out.hashes)) entry.hashes[name] = (await hashValue(v)).value;
        }
        if (out.notes && out.notes.length) entry.notes = out.notes;
        return entry;
    } catch (e) {
        return {
            ...base, ...classifyError(e),
            raw: null, normalized: null, hashAlgorithm: null, hash: null
        };
    }
}

// Which older (pre-harness) result keys belong to which category, and which part of
// them is stable enough to hash. Anything volatile (latencies, viewport size, battery,
// storage usage, IPs, permissions) is left out of these views.
function legacyStableViews(result) {
    const audio = result.audio || {};
    const output = audio.output && !audio.output.error ? audio.output : null;
    return {
        static: {
            clientHints: result.clientHints,
            apis: result.apis,
            webrtc: result.webrtc,
            webgl: result.webgl,
            webgpu: result.webgpu,
            codecs: result.codecs,
            plugins: result.plugins,
            fonts: result.fonts,
            audioSupport: audio.support,
            cssFeatures: result.cssFeatures && result.cssFeatures.hash
        },
        configuration: {
            browser: result.browser,
            screen: result.display && result.display.screen,
            devicePixelRatio: result.display && result.display.devicePixelRatio,
            hardware: result.hardware,
            prefsAndLocale: result.prefsAndLocale,
            // volatile (orientation, display mode, overflow) is window state
            mediaFeatures: result.mediaFeatures && { ...result.mediaFeatures, volatile: undefined },
            speechVoices: result.speechVoices,
            // sampleRate follows the output device; latencies and state are session-dependent
            audioOutput: output && { sampleRate: output.sampleRate, destination: output.destination, analyser: output.analyser }
        },
        behavioral: {
            canvas: result.canvas && result.canvas.hash,
            audioFingerprint: audio.fingerprint,
            webgpuRendering: result.webgpuRendering && result.webgpuRendering.hash,
            jsEngine: result.jsEngine && result.jsEngine.hash,
            textRendering: result.textRendering && result.textRendering.hash
        }
    };
}

// Characteristics that move together. Entropy from members of one group must not be
// added up as if they were independent: the same GPU explains WebGL strings, WebGL
// rendering, WebGPU adapter and codec acceleration at once.
// "legacy" lists older result keys, tests lists ids under result.tests (a test also
// joins a group through its own `groups` field).
const FP_CORRELATION_GROUPS = {
    gpu: { legacy: ["webgl", "webgpu", "webgpuRendering"], description: "GPU, driver and graphics stack" },
    browserEngine: { legacy: ["browser", "clientHints", "apis", "cssFeatures", "jsEngine", "codecs"], description: "Browser build and JavaScript engine" },
    operatingSystem: { legacy: ["fonts", "textRendering", "speechVoices"], description: "OS fonts, text stack and language packs" },
    audioStack: { legacy: ["audio"], description: "Audio engine and output device" },
    display: { legacy: ["display", "mediaFeatures"], description: "Screen, window and display preferences" },
    locale: { legacy: ["prefsAndLocale"], description: "Language, region and time settings" },
    cpu: { legacy: ["jsEngine"], description: "CPU architecture and floating-point behaviour" }
};

async function hashEntries(entries) {
    // entries: { name: value }, undefined values are dropped by stableStringify
    return (await hashValue(entries)).value;
}

// Builds result.characteristics from result.tests and the legacy keys
async function buildCharacteristics(result) {
    const tests = result.tests || {};
    const legacy = legacyStableViews(result);
    const out = {
        schema: 1,
        serialization: "stable-json (sorted keys; -0, NaN, Infinity and BigInt preserved), SHA-256",
        notes: [
            "Categories are hashed separately on purpose. A change in one category (for example a new monitor in configuration) says nothing about the others.",
            "Tests that did not succeed are excluded from the hashes and listed under excluded, so a transient failure never changes a hash.",
            "Members of a correlation group describe the same underlying component. Do not count them as independent signals.",
            "A different hash does not prove a different device, and the same hardware can render differently after a browser, driver or OS update."
        ]
    };

    for (const category of ["static", "configuration", "behavioral"]) {
        const members = {};
        const excluded = [];
        for (const [key, value] of Object.entries(legacy[category])) {
            if (value === undefined) { excluded.push({ id: key, reason: "not collected" }); continue; }
            if (value && value.error) { excluded.push({ id: key, reason: "collector error" }); continue; }
            members[`legacy:${key}`] = (await hashValue(value)).value;
        }
        for (const t of Object.values(tests)) {
            if (t.category !== category) continue;
            // unsupported is a stable fact about the browser; failures and blocks are not
            if (t.status === "success") members[`test:${t.id}`] = t.hash;
            else if (t.status === "unsupported") members[`test:${t.id}`] = "unsupported";
            else excluded.push({ id: t.id, reason: `${t.status}: ${t.reason}` });
        }
        out[category] = {
            members: Object.keys(members).sort(),
            excluded,
            hash: await hashEntries(members)
        };
    }

    out.correlationGroups = {};
    for (const [name, def] of Object.entries(FP_CORRELATION_GROUPS)) {
        const members = {};
        for (const key of def.legacy) {
            const v = result[key];
            if (v === undefined || (v && v.error)) continue;
            members[`legacy:${key}`] = (await hashValue(key === "display" ? v.screen : key === "mediaFeatures" ? { ...v, volatile: undefined } : v)).value;
        }
        for (const t of Object.values(tests)) {
            if (t.status === "success" && t.groups.includes(name)) members[`test:${t.id}`] = t.hash;
        }
        out.correlationGroups[name] = {
            description: def.description,
            members: Object.keys(members).sort(),
            hash: await hashEntries(members)
        };
    }
    return out;
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
 *   screenDetails: false,   // getScreenDetails(): multi-screen info; may trigger a permission prompt
 *   stunServers: [...],     // optional STUN URLs
 *   onProgress: (name) => {} // optional progress callback
 * })
 */
async function runFingerprint(options = {}) {
    const opts = {
        consent: false,
        network: true,
        geolocation: false,
        screenDetails: false,
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
        webgpu: await step("webgpu", getWebGPUInfo),
        webgpuRendering: await step("webgpu rendering", getWebGPURendering),
        cssFeatures: await step("css features", getCssFeatures),
        mediaFeatures: await step("media features", getMediaFeatures),
        jsEngine: await step("javascript engine", getJsEngineInfo),
        textRendering: await step("text rendering", getTextRenderingInfo),
        mediaDevices: await step("media devices", getMediaDevices),
        permissions: await step("permissions", getPermissionStates),
        storageAndPower: await step("storage and power", getStorageAndPower),
        networkInfo: await step("network info", getNetworkInfo)
    };

    // Tests registered by the other fingerprint-*.js scripts. Each has its own status,
    // raw and normalized data and hash; see runRegisteredTest().
    result.tests = {};
    for (const test of FP_TEST_REGISTRY) {
        if (typeof opts.onProgress === "function") {
            try { opts.onProgress(test.id); } catch (e) { /* ignore */ }
        }
        result.tests[test.id] = await runRegisteredTest(test, { result, opts });
    }

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
        // latencies and state follow the output device and session, so they are not part of it
        audio: result.audio && {
            support: result.audio.support,
            output: result.audio.output && !result.audio.output.error
                ? { ...result.audio.output, state: undefined, baseLatency: undefined, outputLatency: undefined }
                : result.audio.output,
            fingerprint: result.audio.fingerprint
        },
        hardware: result.hardware,
        apis: result.apis,
        webrtc: result.webrtc,
        webgl: result.webgl,
        fonts: result.fonts,
        plugins: result.plugins,
        codecs: result.codecs,
        speechVoices: result.speechVoices,
        prefsAndLocale: result.prefsAndLocale,
        webgpu: result.webgpu,
        // hashes only: the rest of these objects is diagnostic detail
        webgpuRendering: result.webgpuRendering && result.webgpuRendering.hash,
        cssFeatures: result.cssFeatures && result.cssFeatures.hash,
        // volatile (orientation, display mode, overflow) is window state, so it is left out
        mediaFeatures: result.mediaFeatures && { ...result.mediaFeatures, volatile: undefined },
        // timing is noisy and not part of jsEngine.hash
        jsEngine: result.jsEngine && result.jsEngine.hash,
        textRendering: result.textRendering && result.textRendering.hash
    };
    // Legacy single hash, kept for compatibility. It mixes categories that change for different
    // reasons and treats correlated signals as independent: prefer result.characteristics.
    result.combinedHash = await hashString(JSON.stringify(stable));

    // Static / configuration / behavioral hashes and correlation groups
    result.characteristics = await safe(() => buildCharacteristics(result));

    return result;
}

// Make it reachable from inline handlers / other scripts
window.runFingerprint = runFingerprint;
