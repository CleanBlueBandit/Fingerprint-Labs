import { Router } from 'express';
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import prisma from '../db/prisma.js';

const router = Router();

const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_BYTES = 72; 
const BCRYPT_ROUNDS = 12;


const DUMMY_HASH = bcrypt.hashSync('not-a-real-password-timing-equalizer', BCRYPT_ROUNDS);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, message: 'Too many login attempts, try again later' }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, message: 'Too many accounts created, try again later' }
});

function isString(value) {
    return typeof value === 'string';
}

function validateRegistration(username, password) {
    if (!isString(username) || !isString(password)) {
        return 'Username and password are required';
    }
    if (!USERNAME_RE.test(username)) {
        return 'Username must be 3-20 characters: letters, numbers, _ or -';
    }
    if (password.length < PASSWORD_MIN_LENGTH) {
        return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
    }
    if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
        return `Password must be at most ${PASSWORD_MAX_BYTES} bytes`;
    }
    return null;
}

function startSession(req, res, next, userId, status, message) {
    req.session.regenerate((err) => {
        if (err) return next(err);

        req.session.userId = userId;

        req.session.save((err) => {
            if (err) return next(err);
            res.status(status).json({ ok: true, message });
        });
    });
}

router.post('/register', registerLimiter, async (req, res, next) => {
    try {
        const { username, password } = req.body ?? {};

        const error = validateRegistration(username, password);
        if (error) {
            return res.status(400).json({ ok: false, message: error });
        }

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const user = await prisma.user.create({
            data: { username, passwordHash },
            select: { id: true }
        });

        startSession(req, res, next, user.id, 201, 'User created successfully');
    } catch (err) {
        if (err.code === 'P2002') {
            return res.status(409).json({ ok: false, message: 'Username already exists' });
        }
        next(err);
    }
});

router.post('/login', loginLimiter, async (req, res, next) => {
    try {
        const { username, password } = req.body ?? {};

        const invalid = () => res.status(401).json({ ok: false, message: 'Invalid username or password' });

        if (!isString(username) || !isString(password) ||
            username.length > 20 || Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
            return invalid();
        }

        const user = await prisma.user.findUnique({ where: { username } });

        const passwordOk = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);

        if (!user || !passwordOk) {
            return invalid();
        }

        startSession(req, res, next, user.id, 200, 'Logged in successfully');
    } catch (err) {
        next(err);
    }
});

// Current user for the logged-in session (used by the dashboard)
router.get('/me', async (req, res, next) => {
    const notLoggedIn = () => res.status(401).json({ ok: false, message: 'Not logged in' });

    if (!req.session?.userId) return notLoggedIn();

    try {
        const user = await prisma.user.findUnique({
            where: { id: req.session.userId },
            select: { id: true, username: true, createdAt: true }
        });

        if (!user) {
            // The account no longer exists, so drop the stale session
            return req.session.destroy((err) => {
                if (err) return next(err);
                res.clearCookie('sid');
                notLoggedIn();
            });
        }

        res.set('Cache-Control', 'no-store');
        res.json({ ok: true, user });
    } catch (err) {
        next(err);
    }
});

router.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
        if (err) return next(err);
        res.clearCookie('sid');
        res.json({ ok: true, message: 'Logged out' });
    });
});

export default router;
