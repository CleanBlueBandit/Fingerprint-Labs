import express from 'express';
import cookieParser from 'cookie-parser';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import 'dotenv/config';
import session from 'express-session';
import pg from 'pg';
import connectPgSimple from 'connect-pg-simple';
import { sendPublic } from './helpers.js';
import authRouter from './routes/auth.js';
import pagesRouter from './routes/pages.js';
import fingerprintRouter from './routes/fingerprint.js';
import srcRouter from './routes/resources.js';
import { requestLogger } from './routes/middleware.js';
import prisma from './db/prisma.js';
import { createTlsFingerprintingServer } from './lib/tls-fingerprint.js';

//#region Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.set('trust proxy', 1);

// With TLS_KEY_FILE and TLS_CERT_FILE set, this process terminates TLS itself and
// records a JA3/JA4 fingerprint of every client handshake. Without them it serves
// plain HTTP, which is what you want behind a proxy that terminates TLS.
const tlsEnabled = Boolean(process.env.TLS_KEY_FILE && process.env.TLS_CERT_FILE);

const httpServer = tlsEnabled
    ? createTlsFingerprintingServer(createHttpsServer({
        key: readFileSync(process.env.TLS_KEY_FILE),
        cert: readFileSync(process.env.TLS_CERT_FILE)
    }, app))
    : createServer(app);

const { Pool } = pg;

const pgPool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const PgSession = connectPgSimple(session);

const sessionStore = new PgSession({
    pool: pgPool,
    tableName: 'session',
    createTableIfMissing: true,
    pruneSessionInterval: 900
});
//#endregion

//#region Middleware
app.use(requestLogger);
app.use(express.json());
app.use(cookieParser());

const sessionMiddleware = session({
    store: sessionStore,
    name: 'sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
    }
});

app.use(sessionMiddleware);

//#endregion

//#region Routes
app.use('/src', srcRouter);
app.use('/auth', authRouter);
app.use('/fingerprint', fingerprintRouter);
app.use('/', pagesRouter);


//#endregion

//#region Server
let shuttingDown = false;

async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;

    console.log(`\n${signal} received. Shutting down server...`);

    const timeout = setTimeout(() => {
        console.error('Shutdown timed out. Forcing exit.');
        process.exit(1);
    }, 10000);

    try {
        if (httpServer.listening) {
            await new Promise((resolve, reject) => {
                httpServer.close((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }

        await sessionStore.close();
        await pgPool.end();

        await prisma.$disconnect();

        clearTimeout(timeout);
        console.log('Server shut down successfully.');

        process.exit(0);
    } catch (error) {
        clearTimeout(timeout);
        console.error('Error during shutdown:', error);

        await sessionStore.close().catch(() => {});
        await pgPool.end().catch(() => {});
        await prisma.$disconnect().catch(() => {});

        process.exit(1);
    }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));



const baseUrl =
    `${process.env.PROTOCOL}://${process.env.HOSTNAME}:${process.env.PORT}`;

httpServer.listen(process.env.PORT, () => {
    console.log(`Server listening at ${baseUrl}`);

    if (tlsEnabled) {
        console.log('TLS enabled: JA3/JA4 fingerprinting is active.');
        if (process.env.PROTOCOL !== 'https') {
            console.warn(`PROTOCOL is "${process.env.PROTOCOL}" but TLS is enabled; set PROTOCOL=https.`);
        }
    }
});
//#endregion