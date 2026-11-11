import prisma from '../db/prisma.js';

let id = 0;

export function authenticate(req, res, next) {
    if (!req.session?.userId) {
        return res.redirect(307, "/login");
    }
    next();
}

export async function authenticateReturn(req, res, next) {
    try {
        const id = req.session.userId;
        const user = await prisma.user.findUnique({
            where: { id }
        });

        if (!user) {
            return res.status(401).json({
                ok: false,
                message: 'User not found'
            });
        }

        req.user = user;
        next();
    } catch (err) {
        next(err);
    }
}

const useColors = Boolean(process.stdout.isTTY) &&
    !process.env.NO_COLOR;

const color = (code, value) =>
    useColors ? `\x1b[${code}m${value}\x1b[0m` : String(value);

const c = {
    reset: (s) => color(0, s),
    bold: (s) => color(1, s),
    dim: (s) => color(2, s),
    gray: (s) => color(90, s),
    red: (s) => color(91, s),
    green: (s) => color(92, s),
    yellow: (s) => color(93, s),
    blue: (s) => color(94, s),
    magenta: (s) => color(95, s),
    cyan: (s) => color(96, s),
    white: (s) => color(97, s),
    bgRed: (s) => color(41, s),
    bgGreen: (s) => color(42, s),
    bgYellow: (s) => color(43, s),
    bgBlue: (s) => color(44, s)
};

const methodColors = {
    GET: c.green,
    POST: c.blue,
    PUT: c.yellow,
    PATCH: c.cyan,
    DELETE: c.red,
    OPTIONS: c.magenta,
    HEAD: c.gray
};

function statusLabel(status) {
    const value = String(status);

    if (status >= 200 && status < 300) {
        return c.bgGreen(c.bold(` ${value} `));
    }

    if (status >= 300 && status < 400) {
        return c.bgBlue(c.bold(` ${value} `));
    }

    if (status >= 400 && status < 500) {
        return c.bgYellow(c.bold(` ${value} `));
    }

    if (status >= 500) {
        return c.bgRed(c.bold(` ${value} `));
    }

    return c.gray(value);
}

function formatDuration(ms) {
    if (ms >= 1000) {
        return c.red(`${(ms / 1000).toFixed(2)}s`);
    }

    if (ms >= 300) {
        return c.yellow(`${ms}ms`);
    }

    return c.green(`${ms}ms`);
}

function timestamp() {
    return c.gray(new Date().toISOString());
}

export function requestLogger(req, res, next) {
    const start = process.hrtime.bigint();
    const time = new Date().toISOString();
    id++;
    const method = req.method;
    const methodColor = methodColors[method] || c.white;


    console.log(
        `${c.gray('REQUEST')} ` +
        `${c.bold(c.white(id))} ` +
        `${methodColor(method.padEnd(7))} ` +
        `${c.cyan(req.originalUrl)} ` +
        `${c.gray('|')} ${c.gray(time)} ` +
        `${c.gray('|')} ${c.magenta('IP')} ${c.white(req.ip)}`
    );

    res.on('finish', () => {
        const duration = Number(
            process.hrtime.bigint() - start
        ) / 1e6;

        const status = res.statusCode;
        const location = res.getHeader('Location');
        const isRedirect =
            [301, 302, 303, 307, 308].includes(status);

        console.log(
            `${c.gray('RESPONSE')} ` +
            `${c.bold(c.white(id))} ` +
            `${methodColor(method.padEnd(7))} ` +
            `${c.cyan(req.originalUrl)} ` +
            `${c.gray('|')} ${c.gray('STATUS')} ${statusLabel(status)} ` +
            `${c.gray('|')} ${c.gray('TIME')} ${c.gray(time)} ` +
            `${c.gray('|')} ${c.gray('DURATION')} ${formatDuration(duration)}` +
            (isRedirect
                ? ` ${c.gray('|')} ${c.blue('→')} ${c.cyan(
                    location ?? '(Location not set)'
                )}`
                : '')
        );
    });

    next();
}
