import { Router } from 'express';
import net from 'node:net';
import rateLimit from 'express-rate-limit';

const router = Router();

// Everything returned here describes the caller's own request and is sent
// back only to that caller. Nothing is stored or logged by this router.

const limiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, message: 'Too many requests, try again later' }
});

// Extra client hints the browser is asked to send on later requests
// (Chromium only, and only on HTTPS or localhost).
const ACCEPT_CH = [
    'Sec-CH-UA-Arch',
    'Sec-CH-UA-Bitness',
    'Sec-CH-UA-Full-Version-List',
    'Sec-CH-UA-Model',
    'Sec-CH-UA-Platform-Version',
    'Sec-CH-UA-WoW64',
    'Sec-CH-UA-Form-Factors',
    'Sec-CH-Prefers-Color-Scheme',
    'Sec-CH-Prefers-Reduced-Motion',
    'Sec-CH-Device-Memory',
    'Sec-CH-DPR',
    'Sec-CH-Viewport-Width',
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

function pickHeaders(headers, predicate) {
    return Object.fromEntries(
        Object.entries(headers).filter(([name]) => predicate(name))
    );
}

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
            version: req.httpVersion,
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

        headers,
        headerOrder,
        headerCount: headerOrder.length,

        groups: {
            proxy: pickHeaders(headers, (name) => PROXY_HEADERS.has(name)),
            clientHints: pickHeaders(headers, (name) => name.startsWith('sec-ch-')),
            fetchMetadata: pickHeaders(headers, (name) => name.startsWith('sec-fetch-')),
            signals: pickHeaders(headers, (name) => MISC_SIGNAL_HEADERS.has(name))
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
                .filter(Boolean)
        },

        cookies: {
            // Names only, never values
            names: Object.keys(req.cookies ?? {}),
            headerLength: (req.headers.cookie || '').length
        }
    });
});

export default router;
