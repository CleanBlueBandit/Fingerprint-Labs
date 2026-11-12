import net from 'node:net';
import { createHash } from 'node:crypto';

// TLS fingerprinting (JA3 and JA4) for connections that Node terminates itself.
//
// Node's TLS API does not expose the ClientHello, so the server listens on a plain
// TCP socket, reads the first TLS record, computes the fingerprints, and then hands
// the connection (with the bytes put back) to the real https server. Express then
// looks the result up by the connection's remote address and port.
//
// This only works when TLS ends at this Node process. Behind a reverse proxy or CDN
// the handshake belongs to the proxy, so it has to compute the fingerprint and
// forward it (see TLS_FINGERPRINT_HEADERS in routes/fingerprint.js).

const MAX_RECORD_LENGTH = 16384 + 2048; // TLS plaintext limit plus some slack
const HELLO_TIMEOUT_MS = 10000;
const MAX_STORED = 20000;

const EXTENSION_NAMES = {
    0: 'server_name',
    5: 'status_request',
    10: 'supported_groups',
    11: 'ec_point_formats',
    13: 'signature_algorithms',
    16: 'alpn',
    18: 'signed_certificate_timestamp',
    21: 'padding',
    23: 'extended_master_secret',
    27: 'compress_certificate',
    35: 'session_ticket',
    43: 'supported_versions',
    45: 'psk_key_exchange_modes',
    51: 'key_share',
    17513: 'application_settings_old',
    17613: 'application_settings',
    65037: 'encrypted_client_hello',
    65281: 'renegotiation_info'
};

const hex4 = (n) => n.toString(16).padStart(4, '0');
const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const md5 = (text) => createHash('md5').update(text).digest('hex');

// GREASE values (RFC 8701): both bytes equal, low nibble 0xA (0x0a0a, 0x1a1a, ... 0xfafa)
export function isGrease(value) {
    return (value & 0x0f0f) === 0x0a0a && (value >> 8) === (value & 0xff);
}

const withoutGrease = (list) => list.filter((v) => !isGrease(v));

// Parses a TLS record that contains a complete ClientHello. Returns null when the
// bytes are not a ClientHello, or the handshake is split across several records.
export function parseClientHello(buf) {
    try {
        if (buf.length < 9 || buf[0] !== 0x16) return null;

        const recordVersion = buf.readUInt16BE(1);
        const recordLength = buf.readUInt16BE(3);
        const recordEnd = Math.min(buf.length, 5 + recordLength);

        let o = 5;
        if (buf[o] !== 0x01) return null; // not a ClientHello
        const handshakeLength = buf.readUIntBE(o + 1, 3);
        o += 4;
        const end = o + handshakeLength;
        if (end > recordEnd) return null; // fragmented across records

        // Every read below goes through need() so a short or malicious hello throws
        const need = (n) => {
            if (o + n > end) throw new RangeError('truncated ClientHello');
        };

        need(2 + 32 + 1);
        const legacyVersion = buf.readUInt16BE(o);
        o += 2 + 32;

        const sessionIdLength = buf[o++];
        need(sessionIdLength);
        o += sessionIdLength;

        need(2);
        const cipherBytes = buf.readUInt16BE(o);
        o += 2;
        need(cipherBytes);
        const cipherSuites = [];
        for (let i = 0; i + 1 < cipherBytes; i += 2) cipherSuites.push(buf.readUInt16BE(o + i));
        o += cipherBytes;

        need(1);
        const compressionLength = buf[o++];
        need(compressionLength);
        const compressionMethods = Array.from(buf.subarray(o, o + compressionLength));
        o += compressionLength;

        const hello = {
            recordVersion,
            legacyVersion,
            sessionIdLength,
            cipherSuites,
            compressionMethods,
            extensions: [],
            sni: null,
            alpn: [],
            supportedVersions: [],
            supportedGroups: [],
            ecPointFormats: [],
            signatureAlgorithms: [],
            hasPsk: false,
            hasEncryptedClientHello: false
        };

        if (o + 2 <= end) {
            const extensionsLength = buf.readUInt16BE(o);
            o += 2;
            const extensionsEnd = Math.min(o + extensionsLength, end);

            while (o + 4 <= extensionsEnd) {
                const type = buf.readUInt16BE(o);
                const length = buf.readUInt16BE(o + 2);
                const data = buf.subarray(o + 4, Math.min(o + 4 + length, extensionsEnd));
                o += 4 + length;

                hello.extensions.push({ type, length });
                decodeExtension(hello, type, data);
            }
        }

        return hello;
    } catch (err) {
        return null;
    }
}

function decodeExtension(hello, type, data) {
    switch (type) {
        case 0: { // server_name: list length, then (name_type, length, name)
            let p = 2;
            while (p + 3 <= data.length) {
                const nameType = data[p];
                const nameLength = data.readUInt16BE(p + 1);
                if (nameType === 0 && p + 3 + nameLength <= data.length) {
                    hello.sni = data.toString('latin1', p + 3, p + 3 + nameLength);
                    break;
                }
                p += 3 + nameLength;
            }
            break;
        }
        case 10: // supported_groups
            for (let p = 2; p + 2 <= data.length; p += 2) hello.supportedGroups.push(data.readUInt16BE(p));
            break;
        case 11: // ec_point_formats
            for (let p = 1; p < data.length; p++) hello.ecPointFormats.push(data[p]);
            break;
        case 13: // signature_algorithms
            for (let p = 2; p + 2 <= data.length; p += 2) hello.signatureAlgorithms.push(data.readUInt16BE(p));
            break;
        case 16: { // alpn: list length, then (length, protocol)
            let p = 2;
            while (p < data.length) {
                const length = data[p];
                if (p + 1 + length > data.length) break;
                hello.alpn.push(data.subarray(p + 1, p + 1 + length));
                p += 1 + length;
            }
            break;
        }
        case 43: // supported_versions (client form: 1-byte length, then 2-byte versions)
            for (let p = 1; p + 2 <= data.length; p += 2) hello.supportedVersions.push(data.readUInt16BE(p));
            break;
        case 41: // pre_shared_key
            hello.hasPsk = true;
            break;
        case 65037: // encrypted_client_hello
            hello.hasEncryptedClientHello = true;
            break;
        default:
    }
}

// JA3: md5 of "version,ciphers,extensions,groups,pointFormats", GREASE removed,
// everything in decimal, lists joined with "-". Chromium shuffles extension order
// per connection, so its JA3 changes between connections; JA4 sorts to avoid that.
export function ja3(hello) {
    const string = [
        hello.legacyVersion,
        withoutGrease(hello.cipherSuites).join('-'),
        withoutGrease(hello.extensions.map((e) => e.type)).join('-'),
        withoutGrease(hello.supportedGroups).join('-'),
        hello.ecPointFormats.join('-')
    ].join(',');

    return { string, hash: md5(string) };
}

const JA4_VERSIONS = {
    0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3', 0x0002: 's2',
    0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3'
};

function ja4AlpnCode(alpn) {
    if (!alpn.length || !alpn[0].length) return '00';

    const first = alpn[0];
    const isAlnum = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
    const firstByte = first[0];
    const lastByte = first[first.length - 1];

    if (isAlnum(firstByte) && isAlnum(lastByte)) {
        return String.fromCharCode(firstByte, lastByte);
    }

    const hex = first.toString('hex');
    return hex[0] + hex[hex.length - 1];
}

// JA4 (FoxIO): a_b_c where
//   a = protocol, TLS version, SNI flag, cipher count, extension count, ALPN
//   b = first 12 hex of sha256 of the sorted cipher suites
//   c = first 12 hex of sha256 of the sorted extensions (without SNI and ALPN)
//       followed by the signature algorithms in their original order
export function ja4(hello) {
    const supported = withoutGrease(hello.supportedVersions);
    const version = JA4_VERSIONS[supported.length ? Math.max(...supported) : hello.legacyVersion] ?? '00';

    const ciphers = withoutGrease(hello.cipherSuites);
    const extensionTypes = withoutGrease(hello.extensions.map((e) => e.type));
    const signatureAlgorithms = withoutGrease(hello.signatureAlgorithms);

    const a = [
        't', // TCP. QUIC (q) is not visible here
        version,
        hello.sni ? 'd' : 'i',
        String(Math.min(ciphers.length, 99)).padStart(2, '0'),
        String(Math.min(extensionTypes.length, 99)).padStart(2, '0'),
        ja4AlpnCode(hello.alpn)
    ].join('');

    const cipherList = [...ciphers].sort((x, y) => x - y).map(hex4).join(',');
    const hashedExtensions = extensionTypes
        .filter((t) => t !== 0x0000 && t !== 0x0010)
        .sort((x, y) => x - y)
        .map(hex4)
        .join(',');
    const signatureList = signatureAlgorithms.map(hex4).join(',');

    const b = ciphers.length ? sha256(cipherList).slice(0, 12) : '000000000000';
    const cInput = hashedExtensions + (signatureList ? `_${signatureList}` : '');
    const c = hashedExtensions ? sha256(cInput).slice(0, 12) : '000000000000';

    return {
        value: `${a}_${b}_${c}`,
        raw: `${a}_${cipherList}_${cInput}`
    };
}

// Readable summary, including the pieces the fingerprints are built from
export function describeClientHello(hello) {
    const ja3Result = ja3(hello);
    const ja4Result = ja4(hello);
    const supported = withoutGrease(hello.supportedVersions);

    return {
        ja3: ja3Result.string,
        ja3Hash: ja3Result.hash,
        ja4: ja4Result.value,
        ja4Raw: ja4Result.raw,
        clientHello: {
            recordVersion: `0x${hex4(hello.recordVersion)}`,
            legacyVersion: `0x${hex4(hello.legacyVersion)}`,
            supportedVersions: supported.map((v) => `0x${hex4(v)}`),
            sni: hello.sni,
            alpn: hello.alpn.map((p) => p.toString('latin1')),
            cipherSuites: withoutGrease(hello.cipherSuites).map((c) => `0x${hex4(c)}`),
            extensions: hello.extensions
                .filter((e) => !isGrease(e.type))
                .map((e) => EXTENSION_NAMES[e.type] ?? `0x${hex4(e.type)}`),
            extensionOrder: withoutGrease(hello.extensions.map((e) => e.type)).map(hex4),
            supportedGroups: withoutGrease(hello.supportedGroups).map((g) => `0x${hex4(g)}`),
            ecPointFormats: hello.ecPointFormats,
            signatureAlgorithms: withoutGrease(hello.signatureAlgorithms).map((s) => `0x${hex4(s)}`),
            compressionMethods: hello.compressionMethods,
            sessionIdLength: hello.sessionIdLength,
            greaseSeen: hello.cipherSuites.some(isGrease) || hello.extensions.some((e) => isGrease(e.type)),
            resumptionOffered: hello.hasPsk,
            encryptedClientHello: hello.hasEncryptedClientHello
        }
    };
}

// ---------------------------------------------------------------------------
// Connection sniffing
// ---------------------------------------------------------------------------

const fingerprints = new Map();

const socketKey = (socket) => `${socket.remoteAddress}:${socket.remotePort}`;

// Looks up the fingerprint recorded for a connection. Accepts the TLS socket that
// Express sees as req.socket (it has the same remote address and port as the
// raw TCP socket the hello was read from).
export function getTlsFingerprint(socket) {
    if (!socket || !socket.remoteAddress) return null;
    return fingerprints.get(socketKey(socket)) ?? null;
}

// Wraps an https.Server. Returns a net.Server: listen on it instead of the https
// server. Each connection's first TLS record is parsed, then everything is replayed
// to the https server so the handshake proceeds normally.
export function createTlsFingerprintingServer(tlsServer) {
    const tcp = net.createServer((socket) => {
        const chunks = [];
        let received = 0;
        let handedOff = false;

        // The raw socket must never crash the process before TLS takes over
        const ignoreError = () => {};
        socket.on('error', ignoreError);

        const handOff = (hello) => {
            if (handedOff) return;
            handedOff = true;
            clearTimeout(timer);
            socket.removeListener('data', onData);
            socket.pause();

            if (hello) {
                const key = socketKey(socket);
                if (fingerprints.size >= MAX_STORED) {
                    fingerprints.delete(fingerprints.keys().next().value);
                }
                fingerprints.set(key, describeClientHello(hello));
                socket.once('close', () => fingerprints.delete(key));
            }

            if (received) socket.unshift(Buffer.concat(chunks));
            tlsServer.emit('connection', socket);
            process.nextTick(() => socket.resume());
        };

        const timer = setTimeout(() => {
            if (!handedOff) socket.destroy();
        }, HELLO_TIMEOUT_MS);

        const onData = (chunk) => {
            chunks.push(chunk);
            received += chunk.length;
            const buf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);

            // Not TLS at all (for example plain HTTP sent to the HTTPS port): let the
            // https server reject it in the usual way
            if (buf[0] !== 0x16) return handOff(null);
            if (buf.length < 5) return;

            const recordLength = buf.readUInt16BE(3);
            if (recordLength > MAX_RECORD_LENGTH) return handOff(null);
            if (buf.length < 5 + recordLength) return; // ClientHello spans several TCP segments

            handOff(parseClientHello(buf));
        };

        socket.on('data', onData);
        socket.once('close', () => clearTimeout(timer));
    });

    // https.Server.close() also drops idle keep-alive connections; a plain net.Server
    // would wait for them, which would stall graceful shutdown
    const closeTcp = tcp.close.bind(tcp);
    tcp.close = (callback) => {
        tlsServer.closeIdleConnections?.();
        return closeTcp(callback);
    };

    return tcp;
}
