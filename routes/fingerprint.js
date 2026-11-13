import { Router } from 'express';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { TLS_FINGERPRINT_HEADERS, readTlsFingerprint, tlsNoteFor } from '../lib/tls-fingerprint.js';
import rateLimit from 'express-rate-limit';
import prisma from '../db/prisma.js';
import { compareFingerprints } from '../lib/fingerprint-compare.js';
import {
    MAX_SAVED_PER_USER,
    extractHashes,
    isPlainObject,
    sanitizeData,
    toSummary
} from '../lib/fingerprint-store.js';

const router = Router();

// GET /fingerprint/info describes the caller's own request and is sent back only to that
// caller; it stores nothing. Saving is separate and explicit: POST /fingerprint/saved stores a
// result the user chose to save, against their own account, and the /saved routes only ever
// read or delete rows that belong to the logged-in user.

const limiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, message: 'Too many requests, try again later' }
});

// Extra client hints the browser is asked to send on later requests
// (Chromium only, and only on HTTPS or localhost).
// Also sent with the /fingerprint page itself (routes/pages.js): browsers only act on
// Accept-CH from page navigations, not from fetch() responses.
export const ACCEPT_CH = [
    'Sec-CH-UA-Arch',
    'Sec-CH-UA-Bitness',
    'Sec-CH-UA-Full-Version-List',
    'Sec-CH-UA-Model',
    'Sec-CH-UA-Platform-Version',
    'Sec-CH-UA-WoW64',
    'Sec-CH-UA-Form-Factors',
    'Sec-CH-UA-Full-Version',
    'Sec-CH-Prefers-Color-Scheme',
    'Sec-CH-Prefers-Reduced-Motion',
    'Sec-CH-Prefers-Reduced-Transparency',
    'Sec-CH-Prefers-Contrast',
    'Sec-CH-Forced-Colors',
    'Sec-CH-Device-Memory',
    'Sec-CH-DPR',
    'Sec-CH-Viewport-Width',
    'Sec-CH-Viewport-Height',
    'Sec-CH-Width',
    'Device-Memory',
    'DPR',
    'Viewport-Width',
    'Width',
    'ECT',
    'RTT',
    'Downlink',
    'Save-Data'
].join(', ');

const SENSITIVE_HEADERS = new Set([
    'authorization',
    'proxy-authorization',
    'x-api-key',
    'x-auth-token'
]);

// Headers that proxies, CDNs and load balancers commonly add
const PROXY_HEADERS = new Set([
    'forwarded',
    'x-forwarded-for',
    'x-forwarded-proto',
    'x-forwarded-host',
    'x-forwarded-port',
    'x-real-ip',
    'via',
    'cf-connecting-ip',
    'cf-connecting-ipv6',
    'cf-ipcountry',
    'cf-ray',
    'cf-visitor',
    'true-client-ip',
    'x-client-ip',
    'x-cluster-client-ip',
    'fastly-client-ip',
    'x-azure-clientip',
    'x-envoy-external-address'
]);

const MISC_SIGNAL_HEADERS = new Set([
    'dnt',
    'sec-gpc',
    'priority',
    'purpose',
    'sec-purpose',
    'save-data',
    'upgrade-insecure-requests',
    'device-memory',
    'dpr',
    'viewport-width',
    'ect',
    'rtt',
    'downlink'
]);

// IP classification
const IP_CLASSES = [
    ['loopback', [['127.0.0.0', 8, 'ipv4'], ['::1', 128, 'ipv6']]],
    ['private', [
        ['10.0.0.0', 8, 'ipv4'],
        ['172.16.0.0', 12, 'ipv4'],
        ['192.168.0.0', 16, 'ipv4'],
        ['fc00::', 7, 'ipv6']
    ]],
    ['link-local', [['169.254.0.0', 16, 'ipv4'], ['fe80::', 10, 'ipv6']]],
    ['carrier-grade-nat', [['100.64.0.0', 10, 'ipv4']]],
    ['unspecified', [['0.0.0.0', 8, 'ipv4'], ['::', 128, 'ipv6']]],
    ['documentation', [
        ['192.0.2.0', 24, 'ipv4'],
        ['198.51.100.0', 24, 'ipv4'],
        ['203.0.113.0', 24, 'ipv4'],
        ['2001:db8::', 32, 'ipv6']
    ]],
    ['multicast', [['224.0.0.0', 4, 'ipv4'], ['ff00::', 8, 'ipv6']]]
].map(([name, subnets]) => {
    const list = new net.BlockList();
    for (const [address, prefix, type] of subnets) {
        list.addSubnet(address, prefix, type);
    }
    return [name, list];
});

function stripV4Mapped(ip) {
    if (typeof ip === 'string' && ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7))) {
        return ip.slice(7);
    }
    return ip;
}

function describeIp(raw) {
    if (typeof raw !== 'string' || !raw) {
        return { address: null, version: null, class: null, ipv4Mapped: false };
    }

    const address = stripV4Mapped(raw);
    const version = net.isIP(address);

    if (!version) {
        return { address: raw, version: null, class: null, ipv4Mapped: false };
    }

    const type = version === 4 ? 'ipv4' : 'ipv6';
    const match = IP_CLASSES.find(([, list]) => list.check(address, type));

    return {
        address,
        version,
        class: match ? match[0] : 'public',
        ipv4Mapped: address !== raw
    };
}

function parseAcceptLanguage(value) {
    if (typeof value !== 'string' || !value) return [];

    return value
        .split(',')
        .map((part) => {
            const [tag, ...params] = part.trim().split(';');
            const qParam = params.map((p) => p.trim()).find((p) => p.startsWith('q='));
            return { tag: tag.trim(), q: qParam ? Number(qParam.slice(2)) : 1 };
        })
        .filter((entry) => entry.tag);
}

// Accept-style headers with q-values, e.g. "text/html,application/xml;q=0.9"
function parseQList(value) {
    if (typeof value !== 'string' || !value) return [];

    return value
        .split(',')
        .map((part) => {
            const [token, ...params] = part.trim().split(';');
            const qParam = params.map((p) => p.trim()).find((p) => p.startsWith('q='));
            return { value: token.trim(), q: qParam ? Number(qParam.slice(2)) : 1 };
        })
        .filter((entry) => entry.value);
}

// "1.1 proxy-a, 2.0 cloudflare" -> [{ version: '1.1', by: 'proxy-a' }, ...]
function parseVia(value) {
    if (typeof value !== 'string' || !value) return [];

    return value
        .split(',')
        .map((hop) => hop.trim())
        .filter(Boolean)
        .map((hop) => {
            const [version, ...by] = hop.split(/\s+/);
            return { version, by: by.join(' ') || null };
        });
}

function sha256Short(text) {
    return createHash('sha256').update(text).digest('hex').slice(0, 32);
}

function pickHeaders(headers, predicate) {
    return Object.fromEntries(
        Object.entries(headers).filter(([name]) => predicate(name))
    );
}

function requireLogin(req, res, next) {
    if (!req.session?.userId) {
        return res.status(401).json({ ok: false, message: 'Not logged in' });
    }
    next();
}

const saveLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, message: 'Too many requests, try again later' }
});

const readLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, message: 'Too many requests, try again later' }
});

const NEWEST_FIRST = [{ createdAt: 'desc' }, { id: 'desc' }];

const meta = (row) => ({ id: row.id, createdAt: row.createdAt });

// Comparison result without the payloads, plus which two rows were compared
function compareRows(a, b) {
    return { ...compareFingerprints(a.data, b.data), a: meta(a), b: meta(b) };
}

function parseId(value) {
    return /^\d{1,9}$/.test(value) ? Number(value) : null;
}

// Save a fingerprint result to the logged-in user's account
router.post('/saved', saveLimiter, requireLogin, async (req, res, next) => {
    try {
        const data = req.body?.data;
        if (!isPlainObject(data) || Object.keys(data).length === 0) {
            return res.status(400).json({ ok: false, message: 'Missing fingerprint data' });
        }

        const userId = req.session.userId;

        const count = await prisma.browserFingerprint.count({ where: { userId } });
        if (count >= MAX_SAVED_PER_USER) {
            return res.status(409).json({
                ok: false,
                message: `You can keep up to ${MAX_SAVED_PER_USER} saved fingerprints. Delete some to save more.`
            });
        }

        // The previous newest one, read before this save so the new row is not compared to itself
        const previous = await prisma.browserFingerprint.findFirst({
            where: { userId },
            orderBy: NEWEST_FIRST
        });

        const row = await prisma.browserFingerprint.create({
            data: { userId, data: sanitizeData(data), ...extractHashes(data) }
        });

        // A comparison that fails must not fail the save
        let comparison = null;
        if (previous) {
            try {
                comparison = compareRows(row, previous);
            } catch (err) {
                console.error('Fingerprint comparison failed:', err);
            }
        }

        res.status(201).json({
            ok: true,
            message: 'Fingerprint saved',
            fingerprint: toSummary(row),
            comparison
        });
    } catch (err) {
        // A user that was deleted while the session was still alive
        if (err.code === 'P2003') {
            return res.status(401).json({ ok: false, message: 'User not found' });
        }
        next(err);
    }
});

// List the logged-in user's saved fingerprints, newest first (hashes only, no payload)
router.get('/saved', readLimiter, requireLogin, async (req, res, next) => {
    try {
        const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);
        const cursor = parseId(String(req.query.cursor ?? ''));

        const rows = await prisma.browserFingerprint.findMany({
            where: { userId: req.session.userId },
            orderBy: NEWEST_FIRST,
            take: limit + 1,
            ...(cursor ? { cursor: { id: cursor }, skip: 0 } : {}),
            select: {
                id: true,
                createdAt: true,
                combinedHash: true,
                staticHash: true,
                configurationHash: true,
                behavioralHash: true,
                schemaVersion: true
            }
        });

        const hasMore = rows.length > limit;
        const page = hasMore ? rows.slice(0, limit) : rows;

        res.set('Cache-Control', 'no-store');
        res.json({
            ok: true,
            fingerprints: page.map(toSummary),
            nextCursor: hasMore ? rows[limit].id : null
        });
    } catch (err) {
        next(err);
    }
});

// How similar the newest saved fingerprint is to the one saved before it
router.get('/saved/compare/latest', readLimiter, requireLogin, async (req, res, next) => {
    try {
        const rows = await prisma.browserFingerprint.findMany({
            where: { userId: req.session.userId },
            orderBy: NEWEST_FIRST,
            take: 2
        });

        res.set('Cache-Control', 'no-store');
        if (rows.length < 2) {
            return res.json({ ok: true, comparison: null, saved: rows.length });
        }
        res.json({ ok: true, comparison: compareRows(rows[0], rows[1]), saved: rows.length });
    } catch (err) {
        next(err);
    }
});

// Compare any two of the user's saved fingerprints: ?a=<id>&b=<id>
router.get('/saved/compare', readLimiter, requireLogin, async (req, res, next) => {
    try {
        const a = parseId(String(req.query.a ?? ''));
        const b = parseId(String(req.query.b ?? ''));
        if (a === null || b === null) {
            return res.status(400).json({ ok: false, message: 'Pass two ids as ?a=<id>&b=<id>' });
        }
        if (a === b) {
            return res.status(400).json({ ok: false, message: 'Pick two different fingerprints' });
        }

        const userId = req.session.userId;
        const [rowA, rowB] = await Promise.all([
            prisma.browserFingerprint.findFirst({ where: { id: a, userId } }),
            prisma.browserFingerprint.findFirst({ where: { id: b, userId } })
        ]);
        if (!rowA || !rowB) return res.status(404).json({ ok: false, message: 'Not found' });

        res.set('Cache-Control', 'no-store');
        res.json({ ok: true, comparison: compareRows(rowA, rowB) });
    } catch (err) {
        next(err);
    }
});

// One saved fingerprint including the full payload
router.get('/saved/:id', readLimiter, requireLogin, async (req, res, next) => {
    try {
        const id = parseId(req.params.id);
        if (id === null) return res.status(400).json({ ok: false, message: 'Invalid id' });

        // userId in the filter is what keeps one user from reading another's rows
        const row = await prisma.browserFingerprint.findFirst({
            where: { id, userId: req.session.userId }
        });
        if (!row) return res.status(404).json({ ok: false, message: 'Not found' });

        res.set('Cache-Control', 'no-store');
        res.json({ ok: true, fingerprint: { ...toSummary(row), data: row.data } });
    } catch (err) {
        next(err);
    }
});

router.delete('/saved/:id', readLimiter, requireLogin, async (req, res, next) => {
    try {
        const id = parseId(req.params.id);
        if (id === null) return res.status(400).json({ ok: false, message: 'Invalid id' });

        const { count } = await prisma.browserFingerprint.deleteMany({
            where: { id, userId: req.session.userId }
        });
        if (count === 0) return res.status(404).json({ ok: false, message: 'Not found' });

        res.json({ ok: true, message: 'Deleted' });
    } catch (err) {
        next(err);
    }
});

router.get('/info', limiter, (req, res) => {
    const socket = req.socket;

    // Headers as received. Cookie values are never returned (names only),
    // and credential headers are redacted.
    const headers = {};
    for (const [name, value] of Object.entries(req.headers)) {
        if (name === 'cookie') continue;
        headers[name] = SENSITIVE_HEADERS.has(name) ? '[redacted]' : value;
    }

    // Original header names, casing and order (differs between browsers)
    const headerOrder = req.rawHeaders.filter((_, index) => index % 2 === 0);

    const tlsFingerprint = readTlsFingerprint(req.headers);

    const tls = socket.encrypted
        ? {
            protocol: socket.getProtocol?.() ?? null,
            cipher: socket.getCipher?.() ?? null,
            alpnProtocol: socket.alpnProtocol || null,
            servername: socket.servername || null,
            sessionReused: socket.isSessionReused?.() ?? null
        }
        : null;

    // Ask the browser to send extra client hints on its next requests
    res.set('Accept-CH', ACCEPT_CH);
    res.set('Cache-Control', 'no-store');

    res.json({
        ok: true,
        serverTime: new Date().toISOString(),

        ip: {
            // What Express resolves, honouring the app's 'trust proxy' setting
            client: describeIp(req.ip),
            // Entries from X-Forwarded-For that Express trusts
            forwardedChain: req.ips.map(describeIp),
            // The raw TCP peer, which is the proxy if you are behind one
            socket: {
                ...describeIp(socket.remoteAddress),
                port: socket.remotePort ?? null,
                family: socket.remoteFamily ?? null
            }
        },

        http: {
            // Protocol of the hop that reached Node. Behind a proxy this is the
            // proxy-to-app connection, not necessarily what the browser used.
            version: req.httpVersion,
            versionMajor: req.httpVersionMajor,
            versionMinor: req.httpVersionMinor,
            // 'h2' / 'http/1.1' when Node terminates TLS and negotiated ALPN
            alpnProtocol: socket.encrypted ? (socket.alpnProtocol || null) : null,
            // HTTP versions of each hop reported by proxies in the Via header
            viaHops: parseVia(req.headers.via),
            priority: req.headers.priority ?? null,
            connection: req.headers.connection ?? null,
            method: req.method,
            protocol: req.protocol,
            secure: req.secure,
            host: req.host,
            hostname: req.hostname,
            originalUrl: req.originalUrl,
            path: req.baseUrl + req.path,
            query: req.query,
            subdomains: req.subdomains,
            xhr: req.xhr
        },

        tls,

        // JA3/JA4 of the TLS handshake, as computed by Vercel's edge and passed in the
        // x-vercel-ja4-digest / x-vercel-ja3-digest headers (see lib/tls-fingerprint.js)
        tlsFingerprint,
        tlsNote: tlsNoteFor(tlsFingerprint),

        headers,
        headerOrder,
        headerCount: headerOrder.length,

        groups: {
            proxy: pickHeaders(headers, (name) => PROXY_HEADERS.has(name)),
            clientHints: pickHeaders(headers, (name) => name.startsWith('sec-ch-')),
            // Sec-CH-Prefers-* (colour scheme, reduced motion, ...) are a subset of clientHints
            preferenceHints: pickHeaders(headers, (name) => name.startsWith('sec-ch-prefers-')),
            fetchMetadata: pickHeaders(headers, (name) => name.startsWith('sec-fetch-')),
            signals: pickHeaders(headers, (name) => MISC_SIGNAL_HEADERS.has(name)),
            // The x-vercel-ja4-digest / x-vercel-ja3-digest headers, when present
            tlsProxy: pickHeaders(headers, (name) => TLS_FINGERPRINT_HEADERS.has(name))
        },

        // Compact request-shape signature: header names in order, plus the values
        // of headers that differ between browsers. Compare it across runs.
        signature: {
            headerOrderHash: sha256Short(headerOrder.join(',')),
            headerOrderLowercaseHash: sha256Short(headerOrder.map((h) => h.toLowerCase()).join(',')),
            acceptHash: sha256Short(String(req.headers.accept ?? '')),
            acceptEncodingHash: sha256Short(String(req.headers['accept-encoding'] ?? '')),
            acceptLanguageHash: sha256Short(String(req.headers['accept-language'] ?? ''))
        },

        parsed: {
            acceptLanguage: parseAcceptLanguage(req.headers['accept-language']),
            acceptEncoding: (req.headers['accept-encoding'] || '')
                .split(',')
                .map((v) => v.trim())
                .filter(Boolean),
            accept: (req.headers.accept || '')
                .split(',')
                .map((v) => v.trim())
                .filter(Boolean),
            // Same Accept header with q-values, plus the raw string for exact comparison
            acceptDetail: parseQList(req.headers.accept),
            acceptRaw: req.headers.accept ?? null,
            // Do Not Track: '1' = opted out, '0' = opted in, absent = not sent.
            // Sec-GPC is the newer Global Privacy Control equivalent.
            doNotTrack: req.headers.dnt ?? null,
            globalPrivacyControl: req.headers['sec-gpc'] ?? null,
            // Request context from Fetch Metadata (site, mode, dest, user)
            fetchMetadata: {
                site: req.headers['sec-fetch-site'] ?? null,
                mode: req.headers['sec-fetch-mode'] ?? null,
                dest: req.headers['sec-fetch-dest'] ?? null,
                user: req.headers['sec-fetch-user'] ?? null
            }
        },

        cookies: {
            // Names only, never values
            names: Object.keys(req.cookies ?? {}),
            headerLength: (req.headers.cookie || '').length
        }
    });
});

export default router;
