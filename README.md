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
- **Browser fingerprint test page** at `/fingerprint` (runs in the browser, behind a consent checkbox)
- **Saved fingerprints**: save a result to your account and view, copy or delete past ones at `/history`
- **Fingerprint comparison**: a weighted similarity score between any two saved fingerprints, and between your newest and the one before it

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

```

| Variable | Purpose |
|---|---|
| `PROTOCOL`, `HOSTNAME`, `PORT` | Used to build the startup URL; `PORT` is also the listen port |
| `NODE_ENV` | Set to `production` to enable `secure` cookies (requires HTTPS) |
| `DATABASE_URL` | Postgres connection string, used by Prisma and the session store |
| `SESSION_SECRET` | Secret used to sign the session cookie |
| `FP_CROSS_ORIGIN_ISOLATION` | Optional. Set to `1` to send COOP/COEP with `/fingerprint` so thread tests can run. |

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
| `npm test` | Node tests for the browser-independent parts of the fingerprint scripts |

## Project Structure

```
.
├── server.js                # App bootstrap, middleware, routes, graceful shutdown
├── helpers.js               # sendPublic / sendPrivate / fileExists path helpers
├── prisma7.config.ts        # Prisma 7 config (schema path, migrations, datasource)
├── prisma/
│   └── schema.prisma        # Database schema (User and BrowserFingerprint models)
├── db/
│   └── prisma.js            # Shared PrismaClient using the pg driver adapter
├── lib/
│   ├── fingerprint-compare.js # Weighted similarity between two saved fingerprints
│   ├── fingerprint-store.js # Hash extraction and payload sanitising for saved fingerprints
│   ├── redact.js            # Hides credential headers (OIDC token, signatures) from responses and saved results
│   ├── tls-fingerprint.js   # Reads and validates the JA3/JA4 headers Vercel sends
│   └── vercel-request.js    # Reads and validates Vercel's IP geolocation and edge routing headers
├── routes/
│   ├── auth.js              # POST /auth/register, /auth/login, /auth/logout; GET /auth/me
│   ├── pages.js             # HTML page routes (/, /login, /register, /dashboard, /fingerprint, /coffee)
│   ├── fingerprint.js       # GET /fingerprint/info, plus the /fingerprint/saved save/list/get/delete API
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
| GET | `/history` | Yes | `images/authenticated/history.html` (your saved fingerprints: copy hashes or the full JSON, view, delete) |
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
- `tls`: protocol, cipher, ALPN and server name of the socket Node sees. This is `null` behind Vercel, because TLS ends at Vercel's edge; see `tlsFingerprint` for the client's handshake.
- `headers`, `headerOrder`, `headerCount`: every header received, plus the original names, casing and order. Credential headers are redacted and `cookie` is left out. That covers `authorization`, `proxy-authorization`, `x-api-key`, `x-auth-token`, anything whose name contains `token`, `secret`, `password`, `signature` or `credential` (on Vercel that includes `x-vercel-oidc-token` and `x-vercel-proxy-signature`), and the `sig=` part of `Forwarded`. Saved fingerprints are scrubbed the same way before they are stored (`lib/redact.js`).
- `groups`: the same headers sorted into `proxy`, `clientHints`, `preferenceHints` (`Sec-CH-Prefers-*`, a subset of `clientHints`), `fetchMetadata`, `signals` (DNT, Sec-GPC, Save-Data, Priority and similar) and `tlsProxy` (the `x-vercel-ja4-digest` / `x-vercel-ja3-digest` headers, see the TLS note below) and `vercel` (the `x-vercel-ip-*` and `x-vercel-id` headers).
- `parsed`: `Accept-Language` with q-values, `Accept-Encoding` and `Accept` as lists; `acceptDetail` (Accept with q-values) and `acceptRaw`; `doNotTrack` and `globalPrivacyControl`; and `fetchMetadata` (`Sec-Fetch-Site/Mode/Dest/User`).
- `signature`: short SHA-256 hashes of the header order (as sent and lowercased), `Accept`, `Accept-Encoding` and `Accept-Language`, for comparing the request's shape across runs.
- `http` also has `versionMajor`/`versionMinor`, `alpnProtocol` (only when Node terminates TLS), `viaHops` (versions reported by proxies in `Via`), `priority` and `connection`. Behind a proxy, `version` is the proxy-to-app hop, not what the browser used.
- `cookies`: cookie names and the size of the cookie header, never values.
- `serverTime`: used by the page to estimate clock skew.

The `/fingerprint` page response and the `/fingerprint/info` response both include an `Accept-CH` header asking Chromium browsers to send extra client hints on later requests (browsers only act on it from page navigations, so the page response is the one that matters): CPU architecture, bitness, full version list, platform version, model, form factors, WoW64, the `Sec-CH-Prefers-*` preferences (colour scheme, reduced motion, reduced transparency, contrast), forced colours, device memory, DPR, viewport and width hints, and the network hints `ECT`, `RTT`, `Downlink` and `Save-Data`. Browsers ignore tokens they don't support. This only works on HTTPS or `localhost`, and the browser then keeps sending them to this origin for the session. The client calls the endpoint a second time when it sees `Accept-CH`, so those headers show up in the result.

**TLS fingerprints (JA3/JA4).** Node can't see the TLS ClientHello when TLS ends at Vercel's edge, so this project doesn't compute fingerprints itself. Vercel computes them for every request (all plans) and passes them to the deployment as headers, which `lib/tls-fingerprint.js` validates and decodes ([Vercel docs](https://vercel.com/docs/vercel-firewall/firewall-concepts)):

| Header | Value |
|---|---|
| `x-vercel-ja4-digest` | JA4 fingerprint (preferred) |
| `x-vercel-ja3-digest` | JA3 fingerprint |

The response has a `tlsFingerprint` object:

- `source`: `"vercel"` when at least one well-formed digest was present, otherwise `null`.
- `trusted`: `true` when running on Vercel (`VERCEL=1`), `false` anywhere else, `null` when there is nothing to report. Off Vercel nothing strips these headers from incoming requests, so a client can send any value it likes; `tlsNote` says so.
- `ja4`, `ja3`: the digests, lowercased. A malformed value is dropped rather than passed through. Vercel documents both headers, but on live requests only `x-vercel-ja4-digest` has been seen, so expect `ja3` to be `null`.
- `ja4Parts`: the readable part of the JA4 decoded: `protocol` (tcp/quic/dtls), `tlsVersion`, `sni`, `cipherCount`, `extensionCount`, `alpn`, plus the `cipherHash` and `extensionHash`.

The raw ClientHello (cipher list, extension order, groups, GREASE/ECH flags) and the JA3/JA4 pre-hash strings are not available any more, because Vercel only exposes the digests.

To try it locally without Vercel, send the header yourself; it is reported with `trusted: false`:

```bash
curl -H 'x-vercel-ja4-digest: t13d1516h2_8daaf6152771_02713d6af862' http://localhost:3000/fingerprint/info
```

Treat the fingerprint as one weak signal. It identifies a TLS client configuration, not a person: users on the same browser build share it, and Vercel's own guidance warns against identifying or blocking someone on a JA4 hash alone. People have reported identical Chrome JA4 values across different countries for exactly this reason. That is why the similarity score gives it a low weight and keeps it out of `combinedHash`. Chromium also shuffles TLS extension order per connection, so JA3 varies between connections while JA4 stays stable.

**IP geolocation and edge routing (Vercel).** On Vercel the response also has a `vercel` object, read from the [request headers Vercel adds](https://vercel.com/docs/headers/request-headers) by `lib/vercel-request.js`:

- `source` and `trusted`: same meaning as in `tlsFingerprint` (`trusted` is `true` only when running on Vercel).
- `geo`: `country`, `continent`, `region`, `city` (decoded), `latitude`, `longitude`, `timezone`, `postalCode` and `asn` (the network operator's autonomous system number) for the client's public IP address, from the `x-vercel-ip-*` headers. Each field is validated and is `null` if it is missing or malformed. `postalCode` is often absent, and `asn` (`x-vercel-ip-as-number`) is missing from Vercel's header reference but was seen on live requests, so don't rely on it staying.
- `edge`: from `x-vercel-id`, the `regions` the request passed through, the `edgeRegion` that received it, the `executionRegion` that ran the function, and the request `id`. Vercel documents the header as the regions hit plus the execution region; the exact layout here is inferred from observed values.

These describe the IP address and network path, not the device. The location is only as accurate as IP geolocation, so a VPN or mobile carrier gives the exit point's location. They are not part of `combinedHash` or the similarity score. Coordinates and postal code are coarse but personal, so treat saved results accordingly.

With `network` on, the client uses `geo.timezone` for one extra consistency check: `consistency.ipTimeZoneMatchesBrowser` compares the UTC offset of the IP's time zone with the browser's (offsets, not names, so aliases like `Asia/Calcutta` and `Asia/Kolkata` match). `false` suggests a VPN, a traveller, or a spoofed browser time zone; `null` means there was no data.

### Saved fingerprints API

A fingerprint is only stored when the user presses **Save to my account** on the test page. These endpoints require a session (`401` otherwise) and only ever touch the logged-in user's own rows (another user's id returns `404`).

| Method | Path | Body / query | Response |
|---|---|---|---|
| POST | `/fingerprint/saved` | `{ data }`: the object returned by `runFingerprint()` | `201` with `{ ok, fingerprint }` (id, createdAt, hashes). `400` for a missing or non-object `data`, `409` once the user holds 200 saved fingerprints, `413` above 5 MB, `429` above 10 per minute |
| GET | `/fingerprint/saved` | `?limit=50` (1-100), `?cursor=<id>` | `{ ok, fingerprints: [...], nextCursor }`, newest first, hashes only (no payload) |
| GET | `/fingerprint/saved/:id` | none | `{ ok, fingerprint: { ..., data } }` with the full payload |
| DELETE | `/fingerprint/saved/:id` | none | `{ ok, message }` |
| GET | `/fingerprint/saved/compare/latest` | none | `{ ok, comparison, saved }`: the newest saved fingerprint compared with the one saved before it. `comparison` is `null` when fewer than two are saved |
| GET | `/fingerprint/saved/compare` | `?a=<id>&b=<id>` | `{ ok, comparison }` for any two of your saved fingerprints. `400` for missing, invalid or identical ids, `404` if either is not yours |

`POST /fingerprint/saved` also returns a `comparison` against the previously saved fingerprint (or `null` for the first one).

### Comparing fingerprints

`lib/fingerprint-compare.js` splits each saved result into about 30 named components plus every registered test, scores each between 0 and 1, and returns the weighted average as a percentage.

- **Weights** (0-10) are in one table at the top of the file. High: canvas (8), installed fonts (8), WebGL (9), WebGL and WebGPU rendering (6), audio fingerprint (6), text rendering (5), hardware and screen (5). Medium: user agent, client hints, codecs, CSS features, JS engine, speech voices (3-4). Low: IP address (1), locale formatting (2), and the connection-dependent request shape and JA4 (3). Tests without an entry use a category weight (static 2, configuration 1.5, behavioral 3).
- **Per-component similarity**: lists (fonts, languages, codecs) are compared as sets, so one added font costs a fraction rather than everything; objects are compared key by key; hashes and strings match exactly or not at all.
- **Not penalised**: a component that is missing, errored or in a state that depends on permissions (`unavailable`, `failed`) on either side is skipped and left out of the average, so a run without network data does not look like a different device. `coverage` is the share of the total weight that could be compared; read a score with low coverage with care. A test that is `unsupported` on both sides counts as a match.
- **Ignored on purpose**: window state (orientation, display mode), audio latencies and state, timing, timestamps, location, permissions and battery.
- **Verdicts**: 99.5% and up Identical, 90% Very similar, 70% Similar, 40% Partly similar, below that Different.
- The result lists every component with its weight, similarity and what changed (for lists, how many items were added and removed), plus a score per group (browser, display, hardware, GPU, audio, canvas and fonts, engine, advanced tests, network). Signals within a group such as the GPU move together, so one real change can lower several components at once.
- The score is a similarity aid, not proof of identity: the same device scores below 100% after a browser, driver or OS update, and different devices with the same hardware and software can score very high.

On `/history`, the newest-vs-previous comparison is shown at the top, and ticking any two entries and pressing **Compare selected** shows the same breakdown for them.
Each row stores the complete payload as JSONB plus `combinedHash`, `staticHash`, `configurationHash`, `behavioralHash` and `schemaVersion` (the `characteristics.schema` value) as indexed columns, extracted by `lib/fingerprint-store.js`. Rows are deleted with the account (`onDelete: Cascade`). The payload includes the IP address, headers and any WebRTC addresses collected in that run, so saved rows are personal data: delete them from the history page when you no longer need them.

### Static assets

Files under `/src/...` are looked up first in `resources/public/`, then in `resources/private/` (which requires login). Anything else under `/src` returns 404. In HTML, always reference assets with a `/src` prefix:

```html
<link rel="stylesheet" href="/src/style.css">
<script src="/src/app.js"></script>
```

## Fingerprint Test Page

`GET /fingerprint` serves a page that collects browser, device and network characteristics and shows them as JSON. Everything is collected in the browser. The server only reports what it sees in the request itself (via `/fingerprint/info`). The collected results stay in the browser unless the user presses **Save to my account**, which sends them to `POST /fingerprint/saved` (see Saved fingerprints API) and stores them against the account. The request logger in `routes/middleware.js` still prints each request's method, URL and IP to the console, as it does for every route.

- `images/authenticated/fingerprint.html` is the page.
- `resources/private/fingerprint-lib.js` holds the collectors and exposes `runFingerprint(options)` and `FINGERPRINT_WARNING`.
- `routes/fingerprint.js` provides `GET /fingerprint/info` (see Fingerprint API above).
- `resources/private/fingerprint-wasm.js`, `fingerprint-media.js`, `fingerprint-text.js` and `fingerprint-env.js` hold the newer tests (see "Tests, statuses and characteristics"). They are loaded after `fingerprint-lib.js` and register their tests with it.
- `resources/private/fingerprint.js` wires the page's checkboxes and buttons to the library, including saving the result.
- `images/authenticated/history.html`, `resources/private/history.js` and `history.css` are the saved-fingerprints page.
- `resources/private/fingerprint.css` adds the layout on top of `style.css`.

`runFingerprint({ consent: true })` throws unless `consent` is exactly `true`, so only pass it after the user has seen `FINGERPRINT_WARNING`. Options:

| Option | Default | Effect |
|---|---|---|
| `consent` | `false` | Required. |
| `network` | `true` | Fetches what this server sees about the request (IP, headers, TLS) from `serverUrl`, gathers WebRTC candidates from a STUN server (a third party), and runs consistency checks between the two. |
| `serverUrl` | `/fingerprint/info` | Endpoint used for the server's view of the request. |
| `geolocation` | `false` | Requests precise location; the browser shows a permission prompt. |
| `screenDetails` | `false` | Runs the `screenDetails` test (`getScreenDetails()`), which can show a permission prompt. Without it the test reports `unavailable`. |
| `stunServers` | Google STUN | STUN URLs used for the WebRTC test. |
| `onProgress` | none | Called with the name of each step as it starts. |

With `network` on, the result has `serverView` (the endpoint's response plus `clientTiming` with round-trip time and estimated clock skew), `webrtcIPs`, and `consistency`, which compares the browser's own claims with what the server received: User-Agent, primary language and language list, client-hint platform, the browser time zone against the IP's time zone (on Vercel), and whether WebRTC's public addresses match the IP the server saw (a mismatch can indicate a VPN or proxy leak).

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

### Tests, statuses and characteristics

The newer collectors are registered tests rather than plain functions. `result.tests.<id>` holds one entry per test:

```
{ id, category, groups, status, reason, error, raw, normalized, hashAlgorithm, hash, hashes?, notes? }
```

- `status` is exactly one of `success`, `unsupported` (the browser has no such API), `unavailable` (the API exists but cannot be used: blocked, insecure context, permissions policy, no hardware, opt-in not given) or `failed` (an exception, a timeout, or a result that contradicts a reference). `reason` says why.
- `raw` is everything measured, including diagnostics and volatile values. `normalized` is only the stable part (sorted, bucketed or quantized) and is what `hash` covers. `hashes` holds extra named hashes that are kept apart on purpose.
- Nothing records how long anything took. Timing is never a matching signal.
- All new hashes are SHA-256 over a canonical serialization (`stableStringify`: sorted keys, `-0`/`NaN`/`Infinity`/BigInt preserved). Without `crypto.subtle` (plain HTTP) a pure-JS SHA-256 is used, so values are comparable across contexts. This replaces the old cyrb53 fallback.

| Test | Category | What it does |
|---|---|---|
| `audioCapabilities` | static | Audio interfaces and prototype members, node factories, which offline sample rates / channel counts / node enumerations are accepted. No device is opened. |
| `audioRendering` | behavioral | Two fixed `OfflineAudioContext` graphs (oscillator → compressor, and automation → biquad → compressor), each rendered twice. Raw Float32 SHA-256 (`hashes.rawSamples`), peak-normalized 16-bit SHA-256 (`quantizedSha256`), stats. `deterministic: false` means the browser adds noise and that variant contributes no hash. Sample rate and latencies stay in `audio.output` (configuration, volatile). |
| `webglRendering` | behavioral | For WebGL1 and WebGL2: an offscreen 128x64 framebuffer of eight 32x32 tiles (highp / mediump / lowp float maths, bilinear and mipmapped texture sampling, three blend set-ups), read with `readPixels`. Raw and quantized SHA-256 per tile and per frame. All GL resources are deleted and the context released. |
| `fontAnalysis` | static | `document.fonts.check()` (compared with a control family, never treated as evidence), canvas and DOM measurements in five scripts, glyph raster hashes and missing-glyph checks. Names that measure identically are one cluster; use `independentFaces`, not the number of names that responded. |
| `hardwareEnvironment` | static | `deviceMemory`, `hardwareConcurrency`. |
| `browserSettings` | configuration | `cookieEnabled`, `doNotTrack`, `globalPrivacyControl`, `pdfViewerEnabled`. |
| `storageEnvironment` | configuration | Quota as a power-of-two bucket, `persisted()`, OPFS presence. `usage` is raw only. |
| `screenDetails` | configuration, opt-in | `getScreenDetails()` when the `screenDetails` option is on. Normalized keeps count and zoom-independent pixel sizes. |
| `wasmCapabilities` | static | Validation of modules using SIMD, relaxed SIMD, atomics/shared memory, bulk memory, reference types, multi-value, tail calls, exceptions, GC, memory64 and more, plus shared-memory and Worker thread execution. |
| `wasmComputation` | behavioral | i32, i64, f32, f64, saturating conversion and SIMD programs, each checked against a JavaScript reference. `normalized` holds only exactly-specified results; `hashes.implementationDefined` holds NaN bits and relaxed-SIMD results, which depend on the CPU and engine. |
| `apiAvailability` | static | WebUSB, WebBluetooth, WebSerial, WebHID, WebXR, MediaDevices, device orientation and motion, `SharedArrayBuffer`, `crossOriginIsolated`: exposure, secure-context and permissions-policy state. |
| `deviceAvailability` | configuration | Prompt-free hardware probes: already-granted USB/serial/HID devices, Bluetooth adapter, XR session support, media device counts, whether sensor events carry data. |
| `mediaCapabilities` | static | A fixed grid of `decodingInfo()` configs (10 video codecs x 6 resolutions, media-source at 1080p30, 6 audio codecs) and WebCodecs `isConfigSupported` with three hardware-acceleration modes, plus `ImageDecoder` types. `supported` is hashed; `smooth` and `powerEfficient` have their own hashes (`hashes.smooth`, `hashes.powerEfficient`) because they can depend on playback history and power state. |
| `indexedDbBehavior`, `cacheApiBehavior` | behavioral | Round trips and key types through a temporary database / cache that is deleted afterwards. |
| `compressionBehavior` | behavioral | Formats accepted by `CompressionStream` and the exact bytes produced for a fixed input. |
| `regexpBehavior` | behavioral | Feature support, case-folding and error text on fixed inputs. |
| `intlData` | static | `Intl` output for fixed locales and a fixed instant (ICU/CLDR data of the build). |
| `localeSettings`, `timezoneBehavior` | configuration | The user's own locale formatting; offsets at fixed past/future instants, this year's transitions, Intl-versus-Date agreement and date parsing. |

Existing keys keep their shape. Additions to them: `display.visualViewport` and `display.normalized` (zoom-independent device pixels; viewport stays separate from `display.screen`), `webgl.availability`, `webgl.hardwareAcceleration` and many more limits per context (`limits`, `maxSamples`, `rgba8RenderbufferSamples`, `extensionLimits`, `defaultFramebuffer`; contexts are now released), `storageAndPower.storage.persisted`, and a `volatile` note on `audio.output`.

`result.characteristics` groups everything by how it behaves:

- `static`, `configuration` and `behavioral` each list their members, the tests that were excluded (and why) and one `hash`. Tests that did not succeed never change a hash; `unsupported` does, because it is a stable fact.
- `correlationGroups` (`gpu`, `browserEngine`, `operatingSystem`, `audioStack`, `display`, `locale`, `cpu`) list members that describe the same component. Do not add up their entropy as if independent.
- `combinedHash` is kept for compatibility but no longer includes audio state and latencies. Prefer `characteristics`.

A different hash does not prove a different device, and identical hardware can render differently after a browser, driver or OS update. `deterministic: false` and `intlAgreesWithDate: false` point to noise injection or spoofing rather than to a new device.

Thread tests need `SharedArrayBuffer`, which browsers only expose to cross-origin isolated pages. Set `FP_CROSS_ORIGIN_ISOLATION=1` to send COOP/COEP with `/fingerprint`. It is off by default because it changes `crossOriginIsolated` and the environment being measured.

Run `npm test` for the checks that need no browser (hashing, serialization, status handling, the WebAssembly programs against JavaScript references, and stubbed audio/WebGL runs). Rendering, fonts, MediaCapabilities and the screen/device probes can only be verified in real browsers.

## Database

Prisma is configured in `prisma7.config.ts`, which points at `prisma/schema.prisma` and `prisma/migrations`. The included schema has two models, `User` and `BrowserFingerprint` (a user's saved fingerprints, see above). `User` looks like this:

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