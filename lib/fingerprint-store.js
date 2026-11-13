// Helpers for saving fingerprints to a user's account. No database access here, so it can be
// tested without Postgres.

export const MAX_SAVED_PER_USER = 200;
export const MAX_PAYLOAD_BYTES = 5 * 1024 * 1024; // keep in sync with the express.json limit in server.js

const HASH_COLUMN_MAX = 64; // VarChar(64) in prisma/schema.prisma

// A hash may be a plain string or { algorithm, value } (what hashString() returns)
function hashOf(value) {
    const raw = value && typeof value === 'object' ? value.value : value;
    return typeof raw === 'string' && raw.length > 0 && raw.length <= HASH_COLUMN_MAX ? raw : null;
}

export function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Pulls the indexed columns out of a fingerprint result produced by runFingerprint()
export function extractHashes(data) {
    const c = isPlainObject(data?.characteristics) ? data.characteristics : {};
    const version = Number.isInteger(c.schema) ? c.schema : null;

    return {
        combinedHash: hashOf(data?.combinedHash),
        staticHash: hashOf(c.static?.hash),
        configurationHash: hashOf(c.configuration?.hash),
        behavioralHash: hashOf(c.behavioral?.hash),
        schemaVersion: version
    };
}

// Postgres JSONB rejects the NUL character, so strip it. The round trip also drops anything
// JSON cannot represent (undefined, functions).
export function sanitizeData(data) {
    return JSON.parse(JSON.stringify(data).replace(/\\u0000/g, ''));
}

// Row shape sent to the list view: hashes and metadata, not the (large) payload
export function toSummary(row) {
    return {
        id: row.id,
        createdAt: row.createdAt,
        combinedHash: row.combinedHash,
        staticHash: row.staticHash,
        configurationHash: row.configurationHash,
        behavioralHash: row.behavioralHash,
        schemaVersion: row.schemaVersion
    };
}
