// Font availability and glyph rendering.
// Loaded after fingerprint-lib.js, which provides the test harness and hashing.
//
// document.fonts.check() does not prove a font is installed: for a family that is not
// loaded as a web font it usually answers true whether or not the system has it. So it is
// recorded, compared against a control, and never used as evidence. The evidence is
// rendering: a font counts as present only if text set in it measures differently from
// the generic fallback it would otherwise land on.

const FONT_CANDIDATES = [
    "Arial", "Segoe UI", "Tahoma", "Verdana", "Times New Roman", "Consolas",
    "Courier New", "Georgia", "Noto Sans", "Roboto", "system-ui"
];
// system-ui is a generic keyword, not a family name: quoting it would make it a family lookup
const FONT_GENERICS = new Set(["system-ui", "sans-serif", "serif", "monospace"]);
const FONT_BASES = ["sans-serif", "serif", "monospace"];
const FONT_SCRIPTS = {
    latin: "Hamburgefonstiv 0123",
    georgian: "გამარჯობა ქართული",
    cyrillic: "Привет, мир Жж",
    arabic: "مرحبا بالعالم",
    cjk: "漢字かなカナ한글"
};
const FONT_SIZE = 48;
const FONT_CONTROL = "__fp_font_that_does_not_exist__";

const fontStack = (family, base) =>
    `${FONT_GENERICS.has(family) ? family : `"${family}"`}, ${base}`;

// Canvas and DOM measurements of every script in one stack, as one comparable string per script
function measureFontStack(ctx, host, stack) {
    const out = {};
    ctx.font = `${FONT_SIZE}px ${stack}`;
    for (const [script, text] of Object.entries(FONT_SCRIPTS)) {
        const m = ctx.measureText(text);
        const canvas = [m.width, m.actualBoundingBoxLeft, m.actualBoundingBoxRight, m.actualBoundingBoxAscent, m.actualBoundingBoxDescent]
            .map((v) => roundTo(v, 3)).join(",");
        const span = document.createElement("span");
        span.style.cssText = `font:${FONT_SIZE}px/normal ${stack};`;
        span.textContent = text;
        host.appendChild(span);
        const box = span.getBoundingClientRect();
        out[script] = `${canvas}|${roundTo(box.width, 3)}x${roundTo(box.height, 3)}`;
    }
    return out;
}

async function getFontAnalysis() {
    if (typeof document === "undefined" || !document.createElement) unsupported("no document");
    const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
    if (!ctx) unavailable("2D canvas context could not be created");

    // withMeasureHost() is synchronous and would remove the host at the first await,
    // so the host is created and removed here around the whole async body
    const host = document.createElement("div");
    host.setAttribute("aria-hidden", "true");
    host.style.cssText = "position:absolute;left:-10000px;top:0;visibility:hidden;pointer-events:none;white-space:nowrap;";
    (document.body || document.documentElement).appendChild(host);
    try {
        // --- 1. document.fonts.check(): recorded, compared with a control, never evidence ---------
        const checkApi = !!(document.fonts && typeof document.fonts.check === "function");
        const check = (family) => {
            if (!checkApi) return null;
            try { return document.fonts.check(`${FONT_SIZE}px ${FONT_GENERICS.has(family) ? family : `"${family}"`}`); }
            catch (e) { return null; }
        };
        const controlCheck = check(FONT_CONTROL);

        // --- 2. Reference measurements of the generic fallbacks -----------------------------------
        const bases = {};
        for (const base of FONT_BASES) bases[base] = measureFontStack(ctx, host, base);

        // --- 3. Each candidate in front of each fallback ------------------------------------------
        const fonts = {};
        const signatures = {}; // full measurement per candidate, used to group aliases
        for (const family of FONT_CANDIDATES) {
            const perBase = {};
            for (const base of FONT_BASES) perBase[base] = measureFontStack(ctx, host, fontStack(family, base));
            signatures[family] = JSON.stringify(perBase);

            // "Differs" is judged on Latin text only: other scripts can differ just because the
            // fallback chain picks a different font for glyphs this one lacks.
            const differsFrom = FONT_BASES.filter((base) => perBase[base].latin !== bases[base].latin);
            const scripts = {};
            for (const script of Object.keys(FONT_SCRIPTS)) {
                // A script "uses fallback" when putting this font first changes nothing, on any fallback
                scripts[script] = FONT_BASES.every((base) => perBase[base][script] === bases[base][script]) ? "fallback" : "own-or-different";
            }
            fonts[family] = {
                kind: FONT_GENERICS.has(family) ? "generic" : "family",
                documentFontsCheck: check(family),
                renderingEvidence: differsFrom.length > 0 ? "renders-distinctly" : "same-as-fallback",
                differsFromFallbacks: differsFrom,
                scripts
            };
        }

        // --- 4. Group names that resolve to the same face ----------------------------------------
        // Two names with an identical measurement on every script and fallback are one signal,
        // not two (for example Arial and a metric-compatible replacement). Fonts that are the
        // same as the fallback carry no signal at all and are not grouped.
        const bySignature = new Map();
        for (const family of FONT_CANDIDATES) {
            if (fonts[family].renderingEvidence !== "renders-distinctly") continue;
            if (!bySignature.has(signatures[family])) bySignature.set(signatures[family], []);
            bySignature.get(signatures[family]).push(family);
        }
        const clusters = [];
        for (const [signature, members] of bySignature) {
            clusters.push({ members: members.slice().sort(), signature });
        }
        clusters.sort((a, b) => a.members.join("+").localeCompare(b.members.join("+")));
        for (const c of clusters) for (const m of c.members) fonts[m].cluster = c.members.join("+");

        // --- 5. Glyph rendering per script, once per cluster --------------------------------------
        // Pixel hashes of the actual glyphs, plus a check for missing-glyph boxes ("tofu").
        const canvas = document.createElement("canvas");
        canvas.width = 360;
        canvas.height = 70;
        const g = canvas.getContext("2d", { willReadFrequently: true });
        const render = async (stack, text) => {
            g.clearRect(0, 0, canvas.width, canvas.height);
            g.font = `40px ${stack}`;
            g.textBaseline = "top";
            g.fillText(text, 4, 4);
            const px = g.getImageData(0, 0, canvas.width, canvas.height).data;
            let ink = 0;
            for (let i = 3; i < px.length; i += 4) if (px[i] !== 0) ink++;
            return { ink, hash: (await hashBytes(px)).value };
        };

        const glyphs = {};
        for (const c of clusters) {
            const stack = fontStack(c.members[0], "sans-serif");
            const tofu = await render(stack, "\u{10FFFF}");
            const perScript = {};
            for (const [script, text] of Object.entries(FONT_SCRIPTS)) {
                const whole = await render(stack, text);
                let missing = 0;
                const chars = Array.from(text.replace(/\s|[,]/g, "")).slice(0, 4);
                for (const ch of chars) {
                    const one = await render(stack, ch);
                    if (one.ink === 0 || one.hash === tofu.hash) missing++;
                }
                perScript[script] = { rasterSha256: whole.hash, inkPixels: whole.ink, sampledGlyphs: chars.length, missingGlyphs: missing };
            }
            glyphs[c.members.join("+")] = perScript;
        }

        // --- 6. Result ---------------------------------------------------------------------------
        const independentFaces = clusters.length;
        const raw = {
            documentFontsApi: checkApi,
            controlFamily: FONT_CONTROL,
            controlCheck,
            fonts,
            clusters: clusters.map((c) => ({ members: c.members })),
            glyphs,
            fallbackBaselines: bases
        };
        const normalized = {
            // true when check() cannot tell a missing family from a present one
            documentFontsCheckInformative: checkApi ? controlCheck === false : null,
            fonts: Object.fromEntries(Object.entries(fonts).map(([name, f]) => [name, {
                kind: f.kind,
                renderingEvidence: f.renderingEvidence,
                cluster: f.cluster || null,
                scripts: f.scripts
            }])),
            clusters: clusters.map((c) => c.members),
            independentFaces,
            glyphs: Object.fromEntries(Object.entries(glyphs).map(([cluster, scripts]) => [cluster,
                Object.fromEntries(Object.entries(scripts).map(([s, v]) => [s, { rasterSha256: v.rasterSha256, missingGlyphs: v.missingGlyphs }]))]))
        };
        return {
            raw,
            normalized,
            notes: [
                "documentFontsCheckInformative=false means check() answered true for a family that cannot exist, so its answers are not evidence of installation.",
                "renderingEvidence compares measurements with the generic fallback. same-as-fallback means not installed OR installed but identical to the fallback here; it does not prove absence.",
                "Names that measure identically on every script and fallback are one cluster. Count independentFaces, not the number of names that responded.",
                "Metrics and pixels move with browser zoom, font smoothing and OS font updates. Treat this as a similarity signal."
            ]
        };
    } finally {
        host.remove();
    }
}

registerTest({ id: "fontAnalysis", category: "static", groups: ["operatingSystem"], run: getFontAnalysis, timeoutMs: 20000 });
