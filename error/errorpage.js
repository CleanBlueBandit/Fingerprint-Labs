import { STATUS_CODES } from 'node:http';

const ERROR_PAGES = {
    400: {
        title: 'Invalid request',
        message: 'Some of the information sent was invalid. Please check your input and try again.',
        action: 'Go back and try again'
    },
    401: {
        title: 'Sign in required',
        message: 'You need to sign in to access this page.',
        action: 'Sign in',
        href: '/login'
    },
    403: {
        title: 'Access denied',
        message: "You don't have permission to access this resource.",
        action: 'Back to dashboard'
    },
    404: {
        title: 'Page not found',
        message: 'The page may have moved, been deleted, or never existed.',
        action: 'Back to dashboard'
    },
    405: {
        title: 'Method not allowed',
        message: 'This request method is not supported for this resource.',
        action: 'Back to dashboard'
    },
    408: {
        title: 'Request timed out',
        message: 'The request took too long. Please try again.',
        action: 'Try again'
    },
    409: {
        title: 'Conflict',
        message: 'This action conflicts with the current state of the resource. Refresh the page and try again.',
        action: 'Back to dashboard'
    },
    413: {
        title: 'Request too large',
        message: 'The submitted data is too large to process.',
        action: 'Back to dashboard'
    },
    415: {
        title: 'Unsupported media type',
        message: 'The submitted content format is not supported.',
        action: 'Back to dashboard'
    },
    418:{
        title: `I'm a teapot`,
        message: 'I refuse to brew coffee because I am a teapot.',
        action: 'Stop poking around and go back to dashboard.'
    },
    422: {
        title: 'Invalid information',
        message: 'Some of the submitted information could not be processed. Please check it and try again.',
        action: 'Go back and try again'
    },
    429: {
        title: 'Too many requests',
        message: 'You have made too many requests in a short period. Please wait a moment before trying again.',
        action: 'Back to dashboard'
    },
    500: {
        title: 'Internal server error',
        message: 'An unexpected error occurred on our side. Please try again later.',
        action: 'Back to dashboard'
    },
    502: {
        title: 'Bad gateway',
        message: 'The server received an invalid response from another service. Please try again later.',
        action: 'Back to dashboard'
    },
    503: {
        title: 'Service unavailable',
        message: 'The service is temporarily unavailable. Please try again shortly.',
        action: 'Back to dashboard'
    },
    504: {
        title: 'Gateway timeout',
        message: 'A server took too long to respond. Please try again later.',
        action: 'Back to dashboard'
    }
};

function escapeHtml(value) {
    return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function renderErrorPage({
    code = null,
    title = 'Error',
    h1 = 'Looks like this link is broken!',
    p = null,
    action = 'Back to dashboard',
    href = '/'
} = {}) {
    let safeHref;
    if(!href) safeHref = "/dashboard"
    else  safeHref = escapeHtml(href);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(title)}</title>
    <link rel="stylesheet" href="/src/style.css">
    <link rel="stylesheet" href="/src/error.css">
</head>
<body class="error-body">
    <main class="error-page">
        ${code !== null
            ? `<div class="error-code">${escapeHtml(code)}</div>`
            : ''
        }
        <h1>${escapeHtml(h1)}</h1>
        ${p ? `<p>${escapeHtml(p)}</p>` : ''}
        <nav class="error-actions" aria-label="Error page actions">
            <a class="primary" href="${safeHref}">${escapeHtml(action)}</a>
        </nav>
    </main>
</body>
</html>`;
}

// Generate a custom error page.
export function errorPage(title = null, h1 = null, p = null) {
    return renderErrorPage({
        title: title ?? 'Error',
        h1: h1 ?? 'Looks like this link is broken!',
        p
    });
}

// Generate an error page from an HTTP status code.
export function errorStatusCode(errCode) {
    const code = Number(errCode);

    // Reject invalid, unknown, and non-error HTTP status codes.
    if (
        !Number.isInteger(code) ||
        code < 400 ||
        code > 599 ||
        !STATUS_CODES[code]
    ) {
        return renderErrorPage({
            code: 500,
            title: '500 - Internal Server Error',
            h1: 'Internal server error',
            p: ERROR_PAGES[500].message
        });
    }

    const status = STATUS_CODES[code];
    const isServerError = code >= 500;

    const details = ERROR_PAGES[code] ?? {
        title: status,
        message: isServerError
            ? 'An unexpected server error occurred. Please try again later.'
            : 'The request could not be completed. Please check your request and try again.',
        action: 'Back to dashboard'
    };

    return renderErrorPage({
        code,
        title: `${code} - ${details.title}`,
        h1: details.title,
        p: details.message,
        action: details.action,
        href: details.href ?? '/'
    });
}

export function respondWithStatusCode(errCode, res){
    return res.status(errCode).send(errorStatusCode(errCode));
}
