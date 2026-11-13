import express from 'express';
import cookieParser from 'cookie-parser';
import { createServer } from 'node:http';
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
import { MAX_PAYLOAD_BYTES } from './lib/fingerprint-store.js';

//#region Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.set('trust proxy', 1);

const httpServer = createServer(app);

const { Pool } = pg;

const pgPool = new Pool({
    connectionString: process.env.DB_DATABASE_URL_POOLED
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
// A full fingerprint result is far bigger than the 100kb default. body-parser skips a request
// that was already parsed, so this has to come before the global parser below.
app.use('/fingerprint/saved', express.json({ limit: MAX_PAYLOAD_BYTES }));
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
});
//#endregion