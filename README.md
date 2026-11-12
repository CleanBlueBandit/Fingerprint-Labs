# Node.js + Express + Prisma Template

A starter template for web apps. It ships with session-based authentication and a PostgreSQL database via Prisma 7, plus a client-side browser fingerprint test page. Build your own pages and API routes on top of it.

## Features

- **Express 5** server with ES modules
- **Authentication**: register, login and logout with bcrypt-hashed passwords (12 rounds)
- **Postgres-backed sessions** via `express-session` and `connect-pg-simple` (24-hour cookie, `httpOnly`, `sameSite: lax`, `secure` in production)
- **Prisma 7** ORM using the `@prisma/adapter-pg` driver adapter
- **Rate limiting** on auth endpoints (10 failed logins per 15 min, 5 registrations per hour per client)
- **Security basics**: input validation, a constant-time dummy hash comparison to blunt username enumeration, session regeneration on login
- **Public vs. authenticated static assets**, with auth enforced for private files
- **Colorized request logger** and **graceful shutdown** (SIGINT/SIGTERM)
- **Custom error pages** generated from HTTP status codes (including `/coffee` → 418)
- **Browser fingerprint test page** at `/fingerprint` (runs entirely in the browser, behind a consent checkbox)

## Tech Stack

| Area | Library |
|---|---|
| Server | Express 5, `cookie-parser` |
| Database | PostgreSQL, Prisma 7, `pg`, `@prisma/adapter-pg` |
| Sessions | `express-session`, `connect-pg-simple` |
| Auth | `bcrypt`, `express-rate-limit` |
| Config | `dotenv` |
| Dev | `nodemon` |

## Prerequisites

- Node.js 20 or newer
- A running PostgreSQL instance
- npm

## Getting Started

### 1. Install dependencies

```bash
npm install
```

The `postinstall` script runs `prisma generate --config prisma7.config.ts`, which creates the client in `generated/prisma/` (git-ignored).

### 2. Configure environment variables

Create a `.env` file in the project root:

```env
# Server
PROTOCOL=http
HOSTNAME=localhost
PORT=3000
NODE_ENV=development

# Database
DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/DBNAME

# Sessions: use a long random string
SESSION_SECRET=change-me-to-a-long-random-string

# Optional: terminate TLS in this process so it can compute JA3/JA4 (see "TLS fingerprints")
# TLS_KEY_FILE=./certs/key.pem
# TLS_CERT_FILE=./certs/cert.pem
```

| Variable | Purpose |
|---|---|
| `PROTOCOL`, `HOSTNAME`, `PORT` | Used to build the startup URL; `PORT` is also the listen port |
| `NODE_ENV` | Set to `production` to enable `secure` cookies (requires HTTPS) |
| `DATABASE_URL` | Postgres connection string, used by Prisma and the session store |
| `SESSION_SECRET` | Secret used to sign the session cookie |
| `TLS_KEY_FILE`, `TLS_CERT_FILE` | Optional. Paths to a PEM private key and certificate. When both are set the server speaks HTTPS itself and fingerprints every TLS handshake (set `PROTOCOL=https` too). Leave unset to serve plain HTTP, for example behind a proxy that terminates TLS. |

Generate a good secret with:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

### 3. Set up the database

Apply the schema in `prisma/schema.prisma` to your database:

```bash
npx prisma migrate dev --config prisma7.config.ts
```

The `session` table is created automatically by `connect-pg-simple` (`createTableIfMissing: true`).

### 4. Run

```bash
npm run dev      # nodemon, auto-restarts on change
# or
node server.js
```

## Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start the server with nodemon |
| `npm run contract:emit` | Runs `prisma contract emit` |
| `npm test` | Placeholder, no tests yet |

## Project Structure

```
.
├── server.js                # App bootstrap, middleware, routes, graceful shutdown
├── helpers.js               # sendPublic / sendPrivate / fileExists path helpers
├── prisma7.config.ts        # Prisma 7 config (schema path, migrations, datasource)
├── prisma/
│   └── schema.prisma        # Database schema (User model)
├── db/
│   └── prisma.js            # Shared PrismaClient using the pg driver adapter
├── lib/
│   └── tls-fingerprint.js   # TLS ClientHello parser, JA3/JA4, and the TCP wrapper that captures them
├── routes/
│   ├── auth.js              # POST /auth/register, /auth/login, /auth/logout; GET /auth/me
│   ├── pages.js             # HTML page routes (/, /login, /register, /dashboard, /fingerprint, /coffee)
│   ├── fingerprint.js       # GET /fingerprint/info: what the server sees about the request
│   ├── resources.js         # Static assets served under /src
│   └── middleware.js        # authenticate, authenticateReturn, requestLogger
├── error/
│   └── errorpage.js         # Status-code based HTML error pages
├── images/                  # HTML pages (despite the name)
│   ├── public/              # Served to anyone (index, login, register, fingerprint)
│   └── authenticated/       # Served only to logged-in users
└── resources/               # CSS/JS/SVG served under /src
    ├── public/              # Public assets (style.css, error.css, login.js, register.js,
    │                        #   fingerprint.js, fingerprint-lib.js, fingerprint.css)
    └── private/             # Auth-only assets
```

## Routes

### Pages

| Method | Path | Auth | Serves |
|---|---|---|---|
| GET | `/` | No | `images/public/index.html` (logged-in users are redirected to `/dashboard`) |
| GET | `/login` | No | `images/public/login.html` |
| GET | `/register` | No | `images/public/register.html` |
| GET | `/dashboard` | Yes | `images/authenticated/dashboard.html` (shows the current user from `/auth/me`, links to the fingerprint test, log out button) |
| GET | `/fingerprint` | Yes | `images/authenticated/fingerprint.html` |
| GET | `/coffee` | No | 418 "I'm a teapot" error page |

Unauthenticated requests to protected pages are redirected (307) to `/login`.

### Auth API

All endpoints accept and return JSON in the shape `{ ok: boolean, message: string }`.

| Method | Path | Body | Success | Errors |
|---|---|---|---|---|
| POST | `/auth/register` | `{ username, password }` | `201` and a new session | `400` validation, `409` username taken, `429` rate limited |
| POST | `/auth/login` | `{ username, password }` | `200` and a new session | `401` invalid credentials, `429` rate limited |
| POST | `/auth/logout` | none | `200`, session destroyed and cookie cleared | none |
| GET | `/auth/me` | none | `200` with `{ ok: true, user: { id, username, createdAt } }` | `401` not logged in (including when the account no longer exists, in which case the stale session is destroyed) |

**Validation rules**

- Username: 3-20 characters, letters, numbers, `_` or `-`
- Password: at least 8 characters, at most 72 bytes (bcrypt's limit)

### Fingerprint API

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/fingerprint/info` | No | JSON describing the request exactly as this server received it (30 requests per minute per client) |

The response is sent only to the caller and nothing is stored. It contains:

- `ip`: the address Express resolves (`client`, honouring `trust proxy`), the trusted `X-Forwarded-For` entries (`forwardedChain`) and the raw TCP peer (`socket`, with port and family). Each address has its IP version and a class (`public`, `private`, `loopback`, `link-local`, `carrier-grade-nat`, and so on). IPv4-mapped IPv6 addresses are unwrapped.
- `http`: HTTP version, method, protocol, host, hostname, original URL, full path, query, subdomains, `xhr`.
- `tls`: protocol, cipher, ALPN and server name, only when Node itself terminates TLS (otherwise `null`).
- `headers`, `headerOrder`, `headerCount`: every header received, plus the original names, casing and order. Credential headers (`authorization`, `proxy-authorization`, `x-api-key`, `x-auth-token`) are redacted and `cookie` is left out.
- `groups`: the same headers sorted into `proxy`, `clientHints`, `preferenceHints` (`Sec-CH-Prefers-*`, a subset of `clientHints`), `fetchMetadata`, `signals` (DNT, Sec-GPC, Save-Data, Priority and similar) and `tlsProxy` (JA3/JA4 headers forwarded by a proxy, see the TLS note below).
- `parsed`: `Accept-Language` with q-values, `Accept-Encoding` and `Accept` as lists; `acceptDetail` (Accept with q-values) and `acceptRaw`; `doNotTrack` and `globalPrivacyControl`; and `fetchMetadata` (`Sec-Fetch-Site/Mode/Dest/User`).
- `signature`: short SHA-256 hashes of the header order (as sent and lowercased), `Accept`, `Accept-Encoding` and `Accept-Language`, for comparing the request's shape across runs.
- `http` also has `versionMajor`/`versionMinor`, `alpnProtocol` (only when Node terminates TLS), `viaHops` (versions reported by proxies in `Via`), `priority` and `connection`. Behind a proxy, `version` is the proxy-to-app hop, not what the browser used.
- `cookies`: cookie names and the size of the cookie header, never values.
- `serverTime`: used by the page to estimate clock skew.

The `/fingerprint` page response and the `/fingerprint/info` response both include an `Accept-CH` header asking Chromium browsers to send extra client hints on later requests (browsers only act on it from page navigations, so the page response is the one that matters): CPU architecture, bitness, full version list, platform version, model, form factors, WoW64, the `Sec-CH-Prefers-*` preferences (colour scheme, reduced motion, reduced transparency, contrast), forced colours, device memory, DPR, viewport and width hints, and the network hints `ECT`, `RTT`, `Downlink` and `Save-Data`. Browsers ignore tokens they don't support. This only works on HTTPS or `localhost`, and the browser then keeps sending them to this origin for the session. The client calls the endpoint a second time when it sees `Accept-CH`, so those headers show up in the result.

**TLS fingerprints (JA3/JA4).** The response has a `tlsFingerprint` object with `source`, `trusted`, `ja3`, `ja3Hash`, `ja4`, `ja4Raw` and a decoded `clientHello` (SNI, ALPN, supported versions, cipher suites, extension order, groups, signature algorithms, whether GREASE and ECH were seen). There are three cases:

1. **Node terminates TLS (`source: "node"`, `trusted: true`).** Node's TLS API doesn't expose the ClientHello, so `lib/tls-fingerprint.js` listens on a plain TCP socket, reads the first TLS record, computes the fingerprints, then replays the bytes to the HTTPS server so the handshake continues normally. Express finds the result by the connection's remote address and port. Enable it by setting `TLS_KEY_FILE` and `TLS_CERT_FILE` and `PROTOCOL=https`. For local testing:

   ```bash
   mkdir certs && openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem -out certs/cert.pem \
     -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
   ```

   It handles ClientHellos split across several TCP segments, and non-TLS traffic on the TLS port is passed to the HTTPS server, which rejects it as usual. It sees TCP only, so QUIC/HTTP3 handshakes (JA4 `q...`) are not covered, and a ClientHello split across multiple TLS records is not parsed.
2. **A proxy or CDN terminates TLS (`source: "proxy-headers"`, `trusted: false`).** Node never sees the handshake, so the proxy has to compute JA3/JA4 and forward them as headers. Any of `cf-ja3-hash`, `cf-ja4`, `x-ja3`, `x-ja3-hash`, `x-ja4`, `x-ja4-hash`, `x-tls-ja3`, `x-tls-ja4`, `ssl-ja3` or `x-ssl-ja3` is reported (also under `groups.tlsProxy`). Some CDNs expose JA3/JA4 to their rules or workers, which can copy them into a header; check your provider's docs and make sure it strips these headers from incoming requests, because any client can send them.
3. **Plain HTTP with nothing forwarded (`source: null`).** `tlsNote` explains why.

JA3 is the MD5 of `version,ciphers,extensions,groups,pointFormats` with GREASE removed. Chromium shuffles the extension order on each connection, so its JA3 changes between connections; JA4 sorts ciphers and extensions, so it stays stable. The JA4 code was checked against the published Chrome values (cipher hash `8daaf6152771`, extension hash `e5627efa2ab1`), and the JA3 code against the JA3 project's sample vector.

### Static assets

Files under `/src/...` are looked up first in `resources/public/`, then in `resources/private/` (which requires login). Anything else under `/src` returns 404. In HTML, always reference assets with a `/src` prefix:

```html
<link rel="stylesheet" href="/src/style.css">
<script src="/src/app.js"></script>
```

## Fingerprint Test Page

`GET /fingerprint` serves a page that collects browser, device and network characteristics and shows them as JSON. Everything is collected in the browser. The server only reports what it sees in the request itself (via `/fingerprint/info`); the collected results are never sent to it and nothing is stored in the database. The request logger in `routes/middleware.js` still prints each request's method, URL and IP to the console, as it does for every route.

- `images/authenticated/fingerprint.html` is the page.
- `resources/private/fingerprint-lib.js` holds the collectors and exposes `runFingerprint(options)` and `FINGERPRINT_WARNING`.
- `routes/fingerprint.js` provides `GET /fingerprint/info` (see Fingerprint API above).
- `resources/private/fingerprint.js` wires the page's checkbox and button to the library.
- `resources/private/fingerprint.css` adds the layout on top of `style.css`.

`runFingerprint({ consent: true })` throws unless `consent` is exactly `true`, so only pass it after the user has seen `FINGERPRINT_WARNING`. Options:

| Option | Default | Effect |
|---|---|---|
| `consent` | `false` | Required. |
| `network` | `true` | Fetches what this server sees about the request (IP, headers, TLS) from `serverUrl`, gathers WebRTC candidates from a STUN server (a third party), and runs consistency checks between the two. |
| `serverUrl` | `/fingerprint/info` | Endpoint used for the server's view of the request. |
| `geolocation` | `false` | Requests precise location; the browser shows a permission prompt. |
| `stunServers` | Google STUN | STUN URLs used for the WebRTC test. |
| `onProgress` | none | Called with the name of each step as it starts. |

With `network` on, the result has `serverView` (the endpoint's response plus `clientTiming` with round-trip time and estimated clock skew), `webrtcIPs`, and `consistency`, which compares the browser's own claims with what the server received: User-Agent, primary language and language list, client-hint platform, and whether WebRTC's public addresses match the IP the server saw (a mismatch can indicate a VPN or proxy leak).

The page and its scripts require login: the route in `routes/pages.js` uses `authenticate`, and the page lives in `images/authenticated/` with its assets in `resources/private/`.

### What gets collected

Beyond the basics (browser, display, canvas, audio, hardware, APIs, WebRTC, WebGL, fonts, plugins, codecs, speech voices, devices, permissions, storage), the result includes:

| Key | What it holds |
|---|---|
| `webgpu` | Adapter `info` (vendor, architecture, device, description, subgroup sizes), supported features, every limit, preferred canvas format, WGSL language features, and whether `high-performance` / `low-power` adapters differ from the default. Browsers may hide or normalise these values, so they don't necessarily describe the physical GPU. `{ supported: false }` when WebGPU is missing. |
| `webgpuRendering` | Renders a 4x MSAA, alpha-blended scene with transcendental maths in the fragment shader into an offscreen texture (no canvas on the page), reads the pixels back and hashes them. Then runs a compute shader of `sin`, `cos`, `exp`, `log`, `pow`, `tanh`, `atan2`, `inverseSqrt` and `fma` and hashes the exact float bits. Also reports any validation error. GPUs, drivers and software rasterizers can differ in blending, MSAA resolve and maths. `{ supported: false }` without WebGPU. |
| `webgl` / `webgl2` `.shaderPrecision` | `getShaderPrecisionFormat()` for vertex and fragment shaders at low/medium/high float and int precision, each with `rangeMin`, `rangeMax` and `precision`. A fragment `highFloat` precision of 0 means `highp` is unsupported there. |
| `mediaFeatures` | Display: `color-gamut`, `dynamic-range`, `video-dynamic-range`, `color`, `color-index`, `monochrome`, `update`. Preferences: `prefers-color-scheme`, `prefers-reduced-motion`, `prefers-reduced-transparency`, `prefers-contrast`, `forced-colors`, `inverted-colors`, `prefers-reduced-data`. Input: `pointer`, `any-pointer`, `hover`, `any-hover`, `scripting`. Foldables: `horizontal-viewport-segments`, `vertical-viewport-segments`, `device-posture`. `vendor` holds `-webkit-`, `-moz-` and `-ms-` queries as plain booleans: Chromium doesn't reject unknown vendor queries, so `false` there can mean unsupported. For the other features, `null` means the browser doesn't support the feature, including browsers that parse it but match none of its values (Chromium does this for `inverted-colors`, `prefers-reduced-data` and `video-dynamic-range`). `volatile` (orientation, display mode, overflow, nav controls) depends on window state and is left out of the combined hash. |
| `cssFeatures` | 169 yes/no probes via `CSS.supports()` and feature detection: properties and values, selectors, at-rules, font technologies and CSS-related APIs, as a count, the list of unsupported items and a bitmap hash. `at-rule()` itself is new, so a blanket "unsupported" for at-rules means the browser can't be asked, not that it lacks them. `computed` holds the number of computed properties, system colour keywords as resolved by the OS and theme, system fonts from the `font` shorthand, default font sizes per generic family (monospace is often 13px) and classic scrollbar size. |
| `jsEngine` | Experimental. Results of 20 `Math` functions on fixed inputs, floating-point and number-formatting edge cases, typed-array behaviour (endianness, NaN bits, clamping, sort order), sort internals (comparator call order, tie handling), error message text and stack format, feature presence, built-in sizes, and a `hash` of all that. `timing` is noisy and excluded from the hash. Differences can come from the engine, its version, the OS or the CPU, and are not guaranteed to tell devices apart. |
| `textRendering` | Canvas `measureText()` metrics for 16 fonts and 5 scripts, canvas text feature flags, DOM line boxes with ascent/descent, fractional layout, SVG text metrics, emoji rendering (pixel bounds, colour, hash, ZWJ and skin-tone ligature support), subpixel positioning and LCD anti-aliasing, and a `hash`. |

The old per-query entries (`darkMode`, `reducedMotion`, `reducedTransparency`, `highContrast`, `forcedColors`, `invertedColors`, `colorGamut*`, `hdr` and `standalone`) that were under `prefsAndLocale.preferences`, and the pointer/hover entries under `hardware.touch`, moved into `mediaFeatures` so nothing is collected twice. `prefsAndLocale` now holds only `locale`.

`consistency` also compares the `Sec-CH-UA-Arch`, `Sec-CH-UA-Bitness`, `Sec-CH-UA-Platform-Version` and `Sec-CH-Prefers-Color-Scheme` headers with what the browser reports through JavaScript (`null` when the header wasn't sent).

`combinedHash` covers the device traits that should stay stable between runs, now including `webgpu`, `webgpuRendering` and `cssFeatures` hashes, `mediaFeatures` (minus `volatile`), `jsEngine.hash` and `textRendering.hash`. The TLS fingerprint is not part of it, because it describes the connection rather than the device. Text metrics can shift with browser zoom or font changes, so treat the hash as a similarity aid rather than an identity.

## Database

Prisma is configured in `prisma7.config.ts`, which points at `prisma/schema.prisma` and `prisma/migrations`. The included schema has a single model:

```prisma
model User {
  id           Int      @id @default(autoincrement())
  username     String   @unique
  passwordHash String
  createdAt    DateTime @default(now())
}
```

Add your own models there, then create and apply a migration:

```bash
npx prisma migrate dev --config prisma7.config.ts
```

The generated client lives in `generated/prisma/` (git-ignored) and is created by `npm install` through the `postinstall` script. Import the shared instance from `db/prisma.js`.

## Graceful Shutdown

On `SIGINT` or `SIGTERM` the server:

1. Closes the HTTP server
2. Closes the session store, the `pg` pool and the Prisma client

If this takes longer than 10 seconds, the process exits with code 1.

## Known Quirks

- `db/prisma.js` imports `../generated/prisma/client.ts`, which matches the generator output in `prisma/schema.prisma`. If you change the output path, update the import.

## Customizing the Template

1. Restyle or extend the landing page (`images/public/index.html`) and dashboard (`images/authenticated/dashboard.html`).
2. Put your CSS, JS and images in `resources/public/` (or the auth-only folder) and reference them with `/src/...`.
3. Add new routers in `routes/` and mount them in `server.js`.
4. Extend the Prisma schema, then run `npx prisma migrate dev --config prisma7.config.ts`.

## License

ISC (see `package.json`).