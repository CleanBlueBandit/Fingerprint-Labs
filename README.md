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
```

| Variable | Purpose |
|---|---|
| `PROTOCOL`, `HOSTNAME`, `PORT` | Used to build the startup URL; `PORT` is also the listen port |
| `NODE_ENV` | Set to `production` to enable `secure` cookies (requires HTTPS) |
| `DATABASE_URL` | Postgres connection string, used by Prisma and the session store |
| `SESSION_SECRET` | Secret used to sign the session cookie |

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
├── routes/
│   ├── auth.js              # POST /auth/register, /auth/login, /auth/logout
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
| GET | `/` | No | `images/public/index.html` |
| GET | `/login` | No | `images/public/login.html` |
| GET | `/register` | No | `images/public/register.html` |
| GET | `/dashboard` | Yes | `images/authenticated/dashboard.html` |
| GET | `/fingerprint` | No | `images/public/fingerprint.html` |
| GET | `/coffee` | No | 418 "I'm a teapot" error page |

Unauthenticated requests to protected pages are redirected (307) to `/login`.

### Auth API

All endpoints accept and return JSON in the shape `{ ok: boolean, message: string }`.

| Method | Path | Body | Success | Errors |
|---|---|---|---|---|
| POST | `/auth/register` | `{ username, password }` | `201` and a new session | `400` validation, `409` username taken, `429` rate limited |
| POST | `/auth/login` | `{ username, password }` | `200` and a new session | `401` invalid credentials, `429` rate limited |
| POST | `/auth/logout` | none | `200`, session destroyed and cookie cleared | none |

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
- `groups`: the same headers sorted into `proxy`, `clientHints`, `fetchMetadata` and `signals` (DNT, Sec-GPC, Save-Data and similar).
- `parsed`: `Accept-Language` with q-values, `Accept-Encoding` and `Accept` as lists.
- `cookies`: cookie names and the size of the cookie header, never values.
- `serverTime`: used by the page to estimate clock skew.

The response includes an `Accept-CH` header asking Chromium browsers to send extra client hints (CPU architecture, bitness, full version list, platform version, device memory, and so on) on later requests. This only works on HTTPS or `localhost`, and the browser then keeps sending them to this origin for the session.

Behind a reverse proxy, `trust proxy` in `server.js` is set to `1`, so Express trusts the last `X-Forwarded-For` entry. Without a proxy in front, a client can set that header itself and change `ip.client`; compare it with `ip.socket` to see the real peer.

### Static assets

Files under `/src/...` are looked up first in `resources/public/`, then in `resources/private/` (which requires login). Anything else under `/src` returns 404. In HTML, always reference assets with a `/src` prefix:

```html
<link rel="stylesheet" href="/src/style.css">
<script src="/src/app.js"></script>
```

## Fingerprint Test Page

`GET /fingerprint` serves a page that collects browser, device and network characteristics and shows them as JSON. Everything is collected in the browser. The server only reports what it sees in the request itself (via `/fingerprint/info`); the collected results are never sent to it and nothing is stored in the database. The request logger in `routes/middleware.js` still prints each request's method, URL and IP to the console, as it does for every route.

- `images/public/fingerprint.html` is the page.
- `resources/public/fingerprint-lib.js` holds the collectors and exposes `runFingerprint(options)` and `FINGERPRINT_WARNING`.
- `routes/fingerprint.js` provides `GET /fingerprint/info` (see Fingerprint API above).
- `resources/public/fingerprint.js` wires the page's checkbox and button to the library.
- `resources/public/fingerprint.css` adds the layout on top of `style.css`.

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

The page is public. To require login, move `fingerprint.html` into `images/authenticated/` and add `authenticate` to the route in `routes/pages.js`.

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

## Still To Add

`GET /dashboard` serves `images/authenticated/dashboard.html`, which doesn't exist yet (only a placeholder `index.html` is there). Create it, or point the route in `routes/pages.js` at the page you want logged-in users to land on.

## Known Quirks

- `db/prisma.js` imports `../generated/prisma/client.ts`, which matches the generator output in `prisma/schema.prisma`. If you change the output path, update the import.

## Customizing the Template

1. Replace the placeholder pages in `images/public/` and `images/authenticated/`.
2. Put your CSS, JS and images in `resources/public/` (or the auth-only folder) and reference them with `/src/...`.
3. Add new routers in `routes/` and mount them in `server.js`.
4. Extend the Prisma schema, then run `npx prisma migrate dev --config prisma7.config.ts`.

## License

ISC (see `package.json`).